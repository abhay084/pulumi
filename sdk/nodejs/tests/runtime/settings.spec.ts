// Copyright 2016-2018, Pulumi Corporation.
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

import * as assert from "assert";
import * as runtime from "../../runtime";

describe("settings", () => {
    beforeEach(() => {
        runtime._reset();
        runtime.setAllConfig({});
    });
    after(() => {
        runtime._reset();
        runtime.setAllConfig({});
    });
    it("runtime options and config are read from and updated via a state object", () => {
        const testOrganization = "TestOrg";
        runtime._setOrganization(testOrganization);
        const testProject = "TestProject";
        runtime._setProject(testProject);
        const testStack = "TestStack";
        runtime._setStack(testStack);
        const isDryRun = true;
        runtime._setIsDryRun(isDryRun);
        const key = "k";
        const val = "v";
        runtime.setConfig(key, val);

        assert.strictEqual(runtime.getOrganization(), testOrganization);
        assert.strictEqual(runtime.getProject(), testProject);
        assert.strictEqual(runtime.getStack(), testStack);
        assert.strictEqual(runtime.isDryRun(), isDryRun);
        assert.strictEqual(runtime.getConfig(key), val);
        assert.strictEqual(runtime.cacheDynamicProviders(), true);
    });
});
