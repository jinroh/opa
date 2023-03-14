// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/compile"
	"github.com/open-policy-agent/opa/ir"

	"github.com/spf13/cobra"

	"github.com/open-policy-agent/opa/util"
)

type depsCommandParams struct {
	capabilities       *capabilitiesFlag
	target             *util.EnumFlag
	bundleMode         bool
	pruneUnused        bool
	optimizationLevel  int
	entrypoints        repeatedStringFlag
	outputFile         string
	revision           stringptrFlag
	ignore             []string
	debug              bool
	algorithm          string
	key                string
	scope              string
	pubKey             string
	pubKeyID           string
	claimsFile         string
	excludeVerifyFiles []string
	plugin             string
}

const (
	depsFormatPretty = "pretty"
	depsFormatJSON   = "json"
)

func init() {
	params := depsCommandParams{
		capabilities: newcapabilitiesFlag(),
		target:       util.NewEnumFlag(compile.TargetRego, compile.Targets),
	}

	depsCommand := &cobra.Command{
		Use:   "deps <query>",
		Short: "Analyze Rego query dependencies",
		Long:  `TODO`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("specify exactly one query argument")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			if err := deps(args, params); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		},
	}

	depsCommand.Flags().VarP(params.target, "target", "t", "set the output bundle target type")
	depsCommand.Flags().BoolVar(&params.pruneUnused, "prune-unused", false, "exclude dependents of entrypoints")
	depsCommand.Flags().BoolVar(&params.debug, "debug", false, "enable debug output")
	depsCommand.Flags().IntVarP(&params.optimizationLevel, "optimize", "O", 0, "set optimization level")
	depsCommand.Flags().VarP(&params.entrypoints, "entrypoint", "e", "set slash separated entrypoint path")
	depsCommand.Flags().VarP(&params.revision, "revision", "r", "set output bundle revision")
	depsCommand.Flags().StringVarP(&params.outputFile, "output", "o", "bundle.tar.gz", "set the output filename")

	addBundleModeFlag(depsCommand.Flags(), &params.bundleMode, false)
	addIgnoreFlag(depsCommand.Flags(), &params.ignore)
	addCapabilitiesFlag(depsCommand.Flags(), params.capabilities)

	RootCommand.AddCommand(depsCommand)
}

func deps(args []string, params depsCommandParams) error {
	var capabilities *ast.Capabilities
	// if capabilities are not provided as a cmd flag,
	// then ast.CapabilitiesForThisVersion must be called
	// within dobuild to ensure custom builtins are properly captured
	if params.capabilities.C != nil {
		capabilities = params.capabilities.C
	} else {
		capabilities = ast.CapabilitiesForThisVersion()
	}

	outputBuf := ioutil.Discard
	compiler := compile.New().
		WithCapabilities(capabilities).
		WithTarget(params.target.String()).
		WithAsBundle(params.bundleMode).
		WithPruneUnused(params.pruneUnused).
		WithOptimizationLevel(params.optimizationLevel).
		WithOutput(outputBuf).
		WithEntrypoints(params.entrypoints.v...).
		WithRegoAnnotationEntrypoints(true).
		WithPaths(args...).
		WithFilter(buildCommandLoaderFilter(params.bundleMode, params.ignore)).
		WithBundleVerificationConfig(nil).
		WithBundleSigningConfig(nil)

	err := compiler.Build(context.Background())
	if err != nil {
		return err
	}

	policy, err := compiler.CompilePlan(context.Background())
	if err != nil {
		return err
	}

	err = ir.Pretty(os.Stderr, policy)
	if err != nil {
		return err
	}

	scanner := newIRScanner(policy)
	scanner.locals = []string{"input", "data"}
	scanner.scanPlan()

	return nil
}

type irScanner struct {
	policy  *ir.Policy
	locals  []string
	cursors map[string]struct{}
}

func newIRScanner(policy *ir.Policy) *irScanner {
	return &irScanner{
		policy:  policy,
		cursors: make(map[string]struct{}),
	}
}

func (s *irScanner) scanPlan() {
	evalPlan := s.policy.Plans.Plans[0]
	for _, block := range evalPlan.Blocks {
		s.scanBlock(block)
	}
}

func (s *irScanner) staticBuiltinFuncs() string {
	panic("TODO")
}

func (s *irScanner) readOperand(lv ir.Operand) string {
	switch x := lv.Value.(type) {
	case ir.Bool:
		// return instruction.I32Const{Value: c.opaBoolAddr(x)}
		panic("TODO")
	case ir.StringIndex:
		return s.policy.Static.Strings[x].Value
	case ir.Local:
		return s.local(x)
	default:
		panic("unreachable")
	}
}

func (s *irScanner) local(i ir.Local) string {
	return s.locals[i]
}

func (s *irScanner) setLocal(i ir.Local, v string) {
	if len(s.locals) <= int(i) {
		locals := s.locals
		s.locals = make([]string, int(i)+1)
		copy(s.locals, locals)
	}
	s.locals[i] = v
}

func printLocals(locals []string) {
	for i, local := range locals {
		fmt.Printf(" %d:%v", i, local)
	}
	fmt.Printf("\n")
}

func (s *irScanner) scanCallStmt(stmt *ir.CallStmt) {
	var fn *ir.Func
	for _, f := range s.policy.Funcs.Funcs {
		if f.Name == stmt.Func {
			fn = f
		}
	}
	for _, arg := range stmt.Args {
		s.cursors[s.readOperand(arg)] = struct{}{}
	}
	if fn != nil {
		localsMax := -1
		for _, param := range fn.Params {
			if int(param) > localsMax {
				localsMax = int(param)
			}
		}
		locals := make([]string, localsMax+1)
		if len(stmt.Args) != len(fn.Params) {
			panic("wrong function call")
		}
		for i, arg := range stmt.Args {
			locals[fn.Params[i]] = s.readOperand(arg)
		}

		ss := newIRScanner(s.policy)
		ss.locals = locals
		for _, block := range fn.Blocks {
			ss.scanBlock(block)
		}
		s.setLocal(stmt.Result, ss.local(fn.Return))
	} else {
		s.setLocal(stmt.Result, "--unknown--")
	}
}

func (s *irScanner) scanBlock(block *ir.Block) {
	for _, stmt := range block.Stmts {
		fmt.Println(stmt)
		switch stmt := stmt.(type) {
		case *ir.ResultSetAddStmt:
			// instrs = append(instrs, instruction.GetLocal{Index: c.lrs})
			// instrs = append(instrs, instruction.GetLocal{Index: c.local(stmt.Value)})
			// instrs = append(instrs, instruction.Call{Index: c.function(opaSetAdd)})

		case *ir.ReturnLocalStmt:
			// instrs = append(instrs, instruction.GetLocal{Index: c.local(stmt.Source)})
			// instrs = append(instrs, instruction.Return{})

		case *ir.BlockStmt:
			for i := range stmt.Blocks {
				s.scanBlock(stmt.Blocks[i])
			}

		case *ir.BreakStmt:

		case *ir.CallStmt:
			s.scanCallStmt(stmt)
		case *ir.CallDynamicStmt:
			// if err := c.compileCallDynamicStmt(stmt, &instrs); err != nil {
			// 	return nil, err
			// }
		case *ir.WithStmt:
			s.scanBlock(stmt.Block)
		case *ir.AssignVarStmt:
			operand := s.readOperand(stmt.Source)
			s.setLocal(stmt.Target, operand)
		case *ir.AssignVarOnceStmt:
			operand := s.readOperand(stmt.Source)
			s.setLocal(stmt.Target, operand)
		case *ir.AssignIntStmt:
			s.setLocal(stmt.Target, strconv.FormatInt(stmt.Value, 10))
		case *ir.ScanStmt:
			s.local(stmt.Source)
			s.local(stmt.Key)
			// if err := c.compileScan(stmt, &instrs); err != nil {
			// 	return nil, err
			// }
		case *ir.NotStmt:
			s.scanBlock(stmt.Block)

		case *ir.DotStmt:
			if loc, ok := stmt.Source.Value.(ir.Local); ok {
				key := s.readOperand(stmt.Key)
				src := s.local(loc)
				dot := fmt.Sprintf("%s.%s", src, key)
				s.setLocal(stmt.Target, dot)
			} else {
				// Booleans and string sources would lead to the BrIf (since opa_value_get
				// on them returns 0), so let's skip trying that.
				// instrs = append(instrs, instruction.Br{Index: 0})
				// break
				panic("TODO")
			}

		case *ir.LenStmt:
			s.setLocal(stmt.Target, "<arr-len>")

		case *ir.MakeNullStmt:
			s.setLocal(stmt.Target, "")
		case *ir.MakeNumberIntStmt:
			s.setLocal(stmt.Target, "")
		case *ir.MakeNumberRefStmt:
			s.setLocal(stmt.Target, "<num>")
		case *ir.MakeArrayStmt:
			s.setLocal(stmt.Target, "<arr>")
		case *ir.MakeObjectStmt:
			s.setLocal(stmt.Target, "<obj>")
		case *ir.MakeSetStmt:
			s.setLocal(stmt.Target, "<set>")

		case *ir.ResetLocalStmt:
			s.setLocal(stmt.Target, "<res>")

		case *ir.EqualStmt:
		case *ir.NotEqualStmt:
		case *ir.NopStmt:
		case *ir.IsArrayStmt:
		case *ir.IsObjectStmt:
		case *ir.IsUndefinedStmt:
		case *ir.IsDefinedStmt:

		case *ir.ArrayAppendStmt:
			// instrs = append(instrs, instruction.GetLocal{Index: c.local(stmt.Array)})
			// instrs = append(instrs, c.instrRead(stmt.Value))
			// instrs = append(instrs, instruction.Call{Index: c.function(opaArrayAppend)})
		case *ir.ObjectInsertStmt:
			// instrs = append(instrs, instruction.GetLocal{Index: c.local(stmt.Object)})
			// instrs = append(instrs, c.instrRead(stmt.Key))
			// instrs = append(instrs, c.instrRead(stmt.Value))
			// instrs = append(instrs, instruction.Call{Index: c.function(opaObjectInsert)})
		case *ir.ObjectInsertOnceStmt:
			// tmp := c.genLocal()
			// instrs = append(instrs, instruction.Block{
			// 	Instrs: []instruction.Instruction{
			// 		instruction.Block{
			// 			Instrs: append([]instruction.Instruction{
			// 				instruction.GetLocal{Index: c.local(stmt.Object)},
			// 				c.instrRead(stmt.Key),
			// 				instruction.Call{Index: c.function(opaValueGet)},
			// 				instruction.TeeLocal{Index: tmp},
			// 				instruction.I32Eqz{},
			// 				instruction.BrIf{Index: 0},
			// 				instruction.GetLocal{Index: tmp},
			// 				c.instrRead(stmt.Value),
			// 				instruction.Call{Index: c.function(opaValueCompare)},
			// 				instruction.I32Eqz{},
			// 				instruction.BrIf{Index: 1},
			// 			}, c.runtimeErrorAbort(stmt.Location, errObjectInsertConflict)...),
			// 		},
			// 		instruction.GetLocal{Index: c.local(stmt.Object)},
			// 		c.instrRead(stmt.Key),
			// 		c.instrRead(stmt.Value),
			// 		instruction.Call{Index: c.function(opaObjectInsert)},
			// 	},
			// })
		case *ir.ObjectMergeStmt:
			// instrs = append(instrs, instruction.GetLocal{Index: c.local(stmt.A)})
			// instrs = append(instrs, instruction.GetLocal{Index: c.local(stmt.B)})
			// instrs = append(instrs, instruction.Call{Index: c.function(opaValueMerge)})
			// instrs = append(instrs, instruction.SetLocal{Index: c.local(stmt.Target)})
		case *ir.SetAddStmt:
			// instrs = append(instrs, instruction.GetLocal{Index: c.local(stmt.Set)})
			// instrs = append(instrs, c.instrRead(stmt.Value))
			// instrs = append(instrs, instruction.Call{Index: c.function(opaSetAdd)})

		default:
			panic(fmt.Errorf("illegal statement: %v", stmt))
		}
		printLocals(s.locals)
		fmt.Println()
	}
}
