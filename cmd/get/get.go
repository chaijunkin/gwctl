/*
Copyright 2024 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package get

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/utils/clock"

	"sigs.k8s.io/gwctl/pkg/common"
	"sigs.k8s.io/gwctl/pkg/extension"
	"sigs.k8s.io/gwctl/pkg/extension/directlyattachedpolicy"
	"sigs.k8s.io/gwctl/pkg/extension/gatewayeffectivepolicy"
	"sigs.k8s.io/gwctl/pkg/extension/notfoundrefvalidator"
	"sigs.k8s.io/gwctl/pkg/extension/refgrantvalidator"
	gwctlflags "sigs.k8s.io/gwctl/pkg/flags"
	"sigs.k8s.io/gwctl/pkg/policymanager"
	"sigs.k8s.io/gwctl/pkg/printer"
	"sigs.k8s.io/gwctl/pkg/topology"
	topologygw "sigs.k8s.io/gwctl/pkg/topology/gateway"
)

func NewCmd(factory common.Factory, iostreams genericiooptions.IOStreams, isDescribe bool) *cobra.Command {
	flags := newGetFlags()

	cmdName := "get"
	if isDescribe {
		cmdName = "describe"
	}

	cmd := &cobra.Command{
		Use:   fmt.Sprintf("%v TYPE [RESOURCE_NAME]", cmdName),
		Short: "Display one or many resources",
		Args:  cobra.RangeArgs(1, 2),
		Run: func(_ *cobra.Command, args []string) {
			o, err := flags.ToOptions(args, factory, iostreams, isDescribe)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v", err)
				os.Exit(1)
			}

			err = o.Run(args)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v", err)
				os.Exit(1)
			}
		},
	}

	flags.resourceBuilderFlags.AddFlags(cmd.Flags())

	if !isDescribe {
		printableAllowedFormats := strings.Join(printer.AllowedOutputFormatsForHelp(), ",")
		cmd.Flags().StringVarP(&flags.outputFormat, "output", "o", "", fmt.Sprintf("Output format. Must be one of: %v", printableAllowedFormats))

		flags.forFlag.AddFlag(cmd.Flags())
	}

	return cmd
}

// getFlags contains the flags used with get command.
type getFlags struct {
	resourceBuilderFlags *genericclioptions.ResourceBuilderFlags
	outputFormat         string
	forFlag              gwctlflags.ForFlag
}

func newGetFlags() *getFlags {
	resourceBuilderFlags := genericclioptions.NewResourceBuilderFlags().
		WithAllNamespaces(false).
		WithLabelSelector("")
	resourceBuilderFlags.FileNameFlags = nil

	return &getFlags{
		resourceBuilderFlags: resourceBuilderFlags,
	}
}

func (f *getFlags) ToOptions(args []string, factory common.Factory, iostreams genericiooptions.IOStreams, isDescribe bool) (*getOptions, error) {
	o := &getOptions{
		isDescribe:    isDescribe,
		factory:       factory,
		IOStreams:     iostreams,
		allNamespaces: *f.resourceBuilderFlags.AllNamespaces,
		labelSelector: *f.resourceBuilderFlags.LabelSelector,
	}

	var err error
	o.resourceTypes, err = parseResourceTypeOrNameArgs(args)
	if err != nil {
		return nil, err
	}

	o.namespace, _, err = factory.KubeConfigNamespace()
	if err != nil {
		return nil, err
	}

	// Parse outputFormat
	o.output, err = printer.ValidateAndReturnOutputFormat(f.outputFormat)
	if err != nil {
		return nil, err
	}

	return o, nil
}

type resourceTypeConfig struct {
	isPolicy      bool
	isPolicyCRD   bool
	hasPolicy     bool
	hasPolicyCRD  bool
	policyOrder   []string // track order of resource types requested
	hasOtherTypes bool     // track if there are non-policy resource types
}

type getOptions struct {
	isDescribe bool

	factory common.Factory

	allNamespaces bool
	namespace     string
	labelSelector string
	output        printer.OutputFormat

	resourceTypes *resourceTypeConfig

	genericclioptions.IOStreams
}

func (o *getOptions) Run(args []string) error {
	// Handle mixed types: separate policy types from other types
	var policyTypes []string
	var otherTypes []string

	// Separate resource types into policy and non-policy
	resourceArg := args[0]
	if strings.Contains(resourceArg, ",") {
		types := strings.Split(resourceArg, ",")
		for _, t := range types {
			t = strings.TrimSpace(t)
			switch t {
			case "policy", "policies", "policycrd", "policycrds":
				policyTypes = append(policyTypes, t)
			default:
				otherTypes = append(otherTypes, t)
			}
		}
	} else {
		switch resourceArg {
		case "policy", "policies", "policycrd", "policycrds":
			policyTypes = append(policyTypes, resourceArg)
		default:
			otherTypes = append(otherTypes, resourceArg)
		}
	}

	// If we have policy types, handle them first
	if len(policyTypes) > 0 {
		policyArgsStr := strings.Join(policyTypes, ",")
		policyArgs := append([]string{policyArgsStr}, args[1:]...)
		if err := o.handlePolicy(policyArgs); err != nil {
			return err
		}
		// Add blank line between different resource type groups
		if len(otherTypes) > 0 {
			fmt.Fprintln(o.IOStreams.Out)
		}
	}

	// If we have other types, handle them with the builder
	if len(otherTypes) == 0 {
		return nil
	}

	otherArgsStr := strings.Join(otherTypes, ",")
	otherArgs := append([]string{otherArgsStr}, args[1:]...)
	infos, err := o.factory.NewBuilder().
		Unstructured().
		Flatten().
		NamespaceParam(o.namespace).DefaultNamespace().AllNamespaces(o.allNamespaces).
		ResourceTypeOrNameArgs(true, otherArgs...).
		LabelSelectorParam(o.labelSelector).
		ContinueOnError().
		Do().
		Infos()
	if err != nil {
		return err
	}

	sources := []*unstructured.Unstructured{}
	for _, info := range infos {
		o, err := runtime.DefaultUnstructuredConverter.ToUnstructured(info.Object) //nolint:govet
		if err != nil {
			return err
		}
		u := &unstructured.Unstructured{Object: o}
		sources = append(sources, u)
	}

	var graph *topology.Graph
	if o.isDescribe || o.output == printer.OutputFormatWide || o.output == printer.OutputFormatGraph {
		graph, err = topology.NewBuilder(common.NewDefaultGroupKindFetcher(o.factory)).
			StartFrom(sources).
			UseRelationships(topologygw.AllRelations).
			Build()
		if err != nil {
			return err
		}

		policyManager := policymanager.New(common.NewDefaultGroupKindFetcher(o.factory))
		if err := policyManager.Init(); err != nil { //nolint:govet
			return err
		}

		err := extension.ExecuteAll(graph, //nolint:govet
			directlyattachedpolicy.NewExtension(policyManager),
			gatewayeffectivepolicy.NewExtension(),
			refgrantvalidator.NewExtension(refgrantvalidator.NewDefaultReferenceGrantFetcher(o.factory)),
			notfoundrefvalidator.NewExtension(),
		)
		if err != nil {
			return err
		}
	} else {
		graph, err = topology.NewBuilder(common.NewDefaultGroupKindFetcher(o.factory)).
			StartFrom(sources).
			Build()
		if err != nil {
			return err
		}
	}

	if o.output == printer.OutputFormatGraph {
		toDotGraph, err := topologygw.ToDot(graph)
		if err != nil {
			return err
		}
		fmt.Fprintf(o.IOStreams.Out, "%v\n", toDotGraph)

		return nil
	}

	return o.printNodes(graph.Sources)
}

func (o *getOptions) handlePolicy(args []string) error {
	policyManager := policymanager.New(common.NewDefaultGroupKindFetcher(o.factory))
	if err := policyManager.Init(); err != nil {
		return err
	}

	// When both policy and policycrd are requested, print them separately in order
	if o.resourceTypes.isPolicy && o.resourceTypes.isPolicyCRD {
		// Print in the order they were requested
		// First pass: collect nodes for each type
		policyNodes := []*topology.Node{}
		crdNodes := []*topology.Node{}

		// Collect policy nodes
		for _, policy := range policyManager.GetPolicies() {
			shouldSkip := (!o.allNamespaces && o.namespace != policy.GKNN().Namespace) ||
				(len(args) == 2 && args[1] != policy.GKNN().Name)
			if shouldSkip {
				continue
			}
			policyNodes = append(policyNodes, encodePolicyAsNode(policy))
		}

		// Collect CRD nodes
		for _, policyCRD := range policyManager.GetCRDs() {
			shouldSkip := len(args) == 2 && (args[1] != policyCRD.CRD.GetName())
			if shouldSkip {
				continue
			}
			node, err := encodePolicyCRDAsNode(policyCRD)
			if err != nil {
				return err
			}
			crdNodes = append(crdNodes, node)
		}

		// Second pass: print in requested order with blank lines only when needed
		hasOutput := false
		for _, resType := range o.resourceTypes.policyOrder {
			var nodesToPrint []*topology.Node
			if resType == "policy" {
				nodesToPrint = policyNodes
			} else if resType == "policycrd" {
				nodesToPrint = crdNodes
			}

			// Only print blank line if we have output and the next section has data
			if len(nodesToPrint) > 0 {
				if hasOutput {
					fmt.Fprintln(o.IOStreams.Out) // Add blank line between different resource types
				}
				if err := o.printNodes(nodesToPrint); err != nil {
					return err
				}
				hasOutput = true
			}
		}
		return nil
	}

	// Single resource type - print normally
	nodes := []*topology.Node{}
	if o.resourceTypes.isPolicy {
		for _, policy := range policyManager.GetPolicies() {
			shouldSkip := (!o.allNamespaces && o.namespace != policy.GKNN().Namespace) ||
				(len(args) == 2 && args[1] != policy.GKNN().Name)
			if shouldSkip {
				continue
			}
			nodes = append(nodes, encodePolicyAsNode(policy))
		}
	}
	if o.resourceTypes.isPolicyCRD {
		for _, policyCRD := range policyManager.GetCRDs() {
			shouldSkip := len(args) == 2 && (args[1] != policyCRD.CRD.GetName())
			if shouldSkip {
				continue
			}
			node, err := encodePolicyCRDAsNode(policyCRD)
			if err != nil {
				return err
			}
			nodes = append(nodes, node)
		}
	}

	return o.printNodes(nodes)
}

func (o *getOptions) printNodes(nodes []*topology.Node) error {
	printerOptions := printer.PrinterOptions{
		OutputFormat: o.output,
		Clock:        clock.RealClock{},
		Description:  o.isDescribe,
		EventFetcher: printer.NewDefaultEventFetcher(o.factory),
	}
	p := printer.NewPrinter(printerOptions)
	defer p.Flush(o.IOStreams.Out)
	for _, node := range topology.SortedNodes(nodes) {
		err := p.PrintNode(node, o.IOStreams.Out)
		if err != nil {
			return err
		}
	}
	return nil
}

func parseResourceTypeOrNameArgs(args []string) (*resourceTypeConfig, error) {
	config := &resourceTypeConfig{
		isPolicy:      false,
		isPolicyCRD:   false,
		hasPolicy:     false,
		hasPolicyCRD:  false,
		policyOrder:   []string{},
		hasOtherTypes: false,
	}

	types := []string{args[0]}
	if strings.Contains(args[0], ",") {
		types = strings.Split(args[0], ",")
	}

	for _, t := range types {
		t = strings.TrimSpace(t)
		switch t {
		case "policy", "policies":
			config.isPolicy = true
			config.hasPolicy = true
			config.policyOrder = append(config.policyOrder, "policy")

		case "policycrd", "policycrds":
			config.isPolicyCRD = true
			config.hasPolicyCRD = true
			config.policyOrder = append(config.policyOrder, "policycrd")

		default:
			// Any other type is tracked as a non-policy type
			config.hasOtherTypes = true
		}
	}

	return config, nil
}

func encodePolicyAsNode(policy *policymanager.Policy) *topology.Node {
	return &topology.Node{
		Object: policy.Unstructured,
		Metadata: map[string]any{
			common.PolicyGK.String(): policy,
		},
	}
}

func encodePolicyCRDAsNode(policyCRD *policymanager.PolicyCRD) (*topology.Node, error) {
	o, err := runtime.DefaultUnstructuredConverter.ToUnstructured(policyCRD.CRD)
	if err != nil {
		return nil, err
	}
	u := &unstructured.Unstructured{Object: o}

	return &topology.Node{
		Object: u,
		Metadata: map[string]any{
			common.PolicyCRDGK.String(): policyCRD,
		},
	}, nil
}
