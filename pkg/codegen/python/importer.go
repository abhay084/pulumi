// Copyright 2016-2020, Pulumi Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package python

import (
	"encoding/json"

	"github.com/pulumi/pulumi/pkg/v3/codegen/schema"
)

// Compatibility mode for Kubernetes 2.0 SDK
const kubernetes20 = "kubernetes20"

// Compatibility mode for tfbridge 2.x SDKs
const tfbridge20 = "tfbridge20"

// PropertyInfo tracks Python-specific information associated with properties in a package.
type PropertyInfo struct {
	MapCase bool `json:"mapCase,omitempty"`
}

// PackageInfo tracks Python-specific information associated with a package.
type PackageInfo struct {
	// PackageName is an override for the name of the generated python package.
	PackageName string `json:"packageName,omitempty"`
	// PythonRequires determines the Python versions that the generated provider supports
	PythonRequires string            `json:"pythonRequires,omitempty"`
	Requires       map[string]string `json:"requires,omitempty"`
	// Readme contains the text for the package's README.md files.
	Readme string `json:"readme,omitempty"`
	// Optional overrides for Pulumi module names
	//
	//    { "flowcontrol.apiserver.k8s.io/v1alpha1": "flowcontrol/v1alpha1" }
	//
	ModuleNameOverrides map[string]string `json:"moduleNameOverrides,omitempty"`
	// Toggle compatibility mode for a specified target.
	Compatibility string `json:"compatibility,omitempty"`
	// Deprecated: This bool is no longer needed since all providers now use input/output classes.
	UsesIOClasses bool `json:"usesIOClasses,omitempty"`
	// Determines whether to make single-return-value methods return an output object or the single value.
	LiftSingleValueMethodReturns bool `json:"liftSingleValueMethodReturns,omitempty"`

	// Respect the Pkg.Version field for emitted code.
	RespectSchemaVersion bool `json:"respectSchemaVersion,omitempty"`

	// If enabled, a pyproject.toml file will be generated.
	PyProject struct {
		Enabled bool `json:"enabled,omitempty"`
	} `json:"pyproject,omitempty"`

	// Specifies what types are used for inputs.
	// Allowed values are the following:
	// - "classes": Args classes only
	// - "classes-and-dicts" (default): TypedDicts side-by-side with Args classes.
	InputTypes string `json:"inputTypes,omitempty"`
}

// Importer implements schema.Language for Python.
var Importer schema.Language = importer(0)

type importer int

// ImportDefaultSpec decodes language-specific metadata associated with a DefaultValue.
func (importer) ImportDefaultSpec(raw json.RawMessage) (interface{}, error) {
	return raw, nil
}

// ImportPropertySpec decodes language-specific metadata associated with a Property.
func (importer) ImportPropertySpec(raw json.RawMessage) (interface{}, error) {
	var info PropertyInfo
	if err := json.Unmarshal([]byte(raw), &info); err != nil {
		return nil, err
	}
	return info, nil
}

// ImportObjectTypeSpec decodes language-specific metadata associated with a ObjectType.
func (importer) ImportObjectTypeSpec(raw json.RawMessage) (interface{}, error) {
	return raw, nil
}

// ImportResourceSpec decodes language-specific metadata associated with a Resource.
func (importer) ImportResourceSpec(raw json.RawMessage) (interface{}, error) {
	return raw, nil
}

// ImportFunctionSpec decodes language-specific metadata associated with a Function.
func (importer) ImportFunctionSpec(raw json.RawMessage) (interface{}, error) {
	return raw, nil
}

// ImportPackageSpec decodes language-specific metadata associated with a Package.
func (importer) ImportPackageSpec(raw json.RawMessage) (interface{}, error) {
	var info PackageInfo
	if err := json.Unmarshal([]byte(raw), &info); err != nil {
		return nil, err
	}
	return info, nil
}
