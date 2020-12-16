// Copyright 2018 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mongodbadapter

import (
	"fmt"
	"os"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	"go.mongodb.org/mongo-driver/bson"
)

var testDbURL = os.Getenv("TEST_MONGODB_URL")

func getDbURL() string {
	if testDbURL == "" {
		testDbURL = "127.0.0.1:27017"
	}
	return testDbURL
}

func testGetPolicy(t *testing.T, e *casbin.Enforcer, res [][]string) {
	t.Helper()
	myRes := e.GetPolicy()
	t.Log("Policy: ", myRes)

	if !util.Array2DEquals(res, myRes) {
		t.Error("Policy: ", myRes, ", supposed to be ", res)
	}
}

func initPolicy(t *testing.T) {
	// Because the DB is empty at first,
	// so we need to load the policy from the file adapter (.CSV) first.
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	if err != nil {
		panic(err)
	}

	a, err := NewAdapter(getDbURL())
	if err != nil {
		panic(err)
	}
	// This is a trick to save the current policy to the DB.
	// We can't call e.SavePolicy() because the adapter in the enforcer is still the file adapter.
	// The current policy means the policy in the Casbin enforcer (aka in memory).
	err = a.SavePolicy(e.GetModel())
	if err != nil {
		panic(err)
	}

	// Clear the current policy.
	e.ClearPolicy()
	testGetPolicy(t, e, [][]string{})

	// Load the policy from DB.
	err = a.LoadPolicy(e.GetModel())
	if err != nil {
		panic(err)
	}
	testGetPolicy(t, e, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
	},
	)
}

func TestAdapter(t *testing.T) {
	initPolicy(t)

	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	a, err := NewAdapter(getDbURL())
	if err != nil {
		panic(err)
	}

	e, err := casbin.NewEnforcer("examples/rbac_model.conf", a)
	if err != nil {
		panic(err)
	}
	testGetPolicy(t, e, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
		},
	)
	// AutoSave is enabled by default.
	// Now we disable it.
	e.EnableAutoSave(false)
	// Because AutoSave is disabled, the policy change only affects the policy in Casbin enforcer,
	// it doesn't affect the policy in the storage.
	e.AddPolicy("alice", "data1", "write")
	// Reload the policy from the storage to see the effect.
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	// This is still the original policy.
	testGetPolicy(t, e, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
		},
	)

	// Now we enable the AutoSave.
	e.EnableAutoSave(true)

	// Because AutoSave is enabled, the policy change not only affects the policy in Casbin enforcer,
	// but also affects the policy in the storage.
	e.AddPolicy("alice", "data1", "write")
	// Reload the policy from the storage to see the effect.
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	// The policy has a new rule: {"alice", "data1", "write"}.
	testGetPolicy(t, e, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
		{"alice", "data1", "write"},
		},
	)	

	// Remove the added rule.
	e.RemovePolicy("alice", "data1", "write")
	if err := a.RemovePolicy("p", "p", []string{"alice", "data1", "write"}); err != nil {
		t.Errorf("Expected RemovePolicy() to be successful; got %v", err)
	}
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
		},
	)

	// Remove "data2_admin" related policy rules via a filter.
	// Two rules: {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"} are deleted.
	e.RemoveFilteredPolicy(0, "data2_admin")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		},
	)

	e.RemoveFilteredPolicy(1, "data1")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{{"bob", "data2", "write"}})

	e.RemoveFilteredPolicy(2, "write")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{})
}

func TestAddPolicies(t *testing.T) {
	initPolicy(t)

	a, err := NewAdapter(getDbURL())
	if err != nil {
		panic(err)
	}

	e, err := casbin.NewEnforcer("examples/rbac_model.conf", a)
	if err != nil {
		panic(err)
	}

	testGetPolicy(t, e, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
		},
	)
	a.AddPolicies("p","p",[][]string{
		{"bob", "data2", "read"},
		{"alice", "data2", "write"},
		{"alice", "data2", "read"},
		{"bob", "data1", "write"},
		{"bob", "data1", "read"},
		},
	)

	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}

	testGetPolicy(t, e, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"}, 
		{"data2_admin", "data2", "write"},
		{"bob", "data2", "read"},
		{"alice", "data2", "write"},
		{"alice", "data2", "read"},
		{"bob", "data1", "write"},
		{"bob", "data1", "read"},
		},
	)

	// Remove the added rule.
	if err := a.RemovePolicies("p", "p", [][]string{
		{"bob", "data2", "read"},
		{"alice", "data2", "write"},
		{"alice", "data2", "read"},
		{"bob", "data1", "write"},
		{"bob", "data1", "read"},
	}); err != nil {
		t.Errorf("Expected RemovePolicies() to be successful; got %v", err)
	}
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"}, 
		{"data2_admin", "data2", "write"},
		},
		)
}

func TestDeleteFilteredAdapter(t *testing.T) {
	a, err := NewFilteredAdapter(getDbURL())
	if err != nil {
		panic(err)
	}

	e, err := casbin.NewEnforcer("examples/rbac_tenant_service.conf", a)
	if err != nil {
		panic(err)
	}

	e.AddPolicy("domain1", "alice", "data3", "read", "accept", "service1")
	e.AddPolicy("domain1", "alice", "data3", "write", "accept", "service2")

	// Reload the policy from the storage to see the effect.
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	// The policy has a new rule: {"alice", "data1", "write"}.
	testGetPolicy(t, e, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
		{"domain1", "alice", "data3", "read", "accept", "service1"},
		{"domain1", "alice", "data3", "write", "accept", "service2"},
	},
	)
	// test RemoveFiltered Policy with "" fileds
	e.RemoveFilteredPolicy(0, "domain1", "", "", "read")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
		{"domain1", "alice", "data3", "write", "accept", "service2"},
	},
	)

	e.RemoveFilteredPolicy(0, "domain1", "", "", "", "", "service2")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
	},
	)
}

func TestFilteredAdapter(t *testing.T) {
	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	a, err := NewFilteredAdapter(getDbURL())
	if err != nil {
		panic(err)
	}

	e, err := casbin.NewEnforcer("examples/rbac_model.conf", a)
	if err != nil {
		panic(err)
	}
	
	// Load filtered policies from the database.
	e.AddPolicy("alice", "data1", "write")
	e.AddPolicy("bob", "data2", "write")
	// Reload the filtered policy from the storage.
	filter := &bson.M{"v0": "bob"}
	if err := e.LoadFilteredPolicy(filter); err != nil {
		t.Errorf("Expected LoadFilteredPolicy() to be successful; got %v", err)
	}
	// Only bob's policy should have been loaded
	testGetPolicy(t, e, [][]string{{"bob", "data2", "write"}})

	// Verify that alice's policy remains intact in the database.
	filter = &bson.M{"v0": "alice"}
	if err := e.LoadFilteredPolicy(filter); err != nil {
		t.Errorf("Expected LoadFilteredPolicy() to be successful; got %v", err)
	}
	// Only alice's policy should have been loaded,
	testGetPolicy(t, e, [][]string{
		{"alice", "data1", "read"},
		{"alice", "data1", "write"},
		},
	)

	// Test safe handling of SavePolicy when using filtered policies.
	if err := e.SavePolicy(); err == nil {
		t.Errorf("Expected SavePolicy() to fail for a filtered policy")
	}
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	if err := e.SavePolicy(); err != nil {
		t.Errorf("Expected SavePolicy() to be successful; got %v", err)
	}

	e.RemoveFilteredPolicy(2, "write")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{
		{"alice", "data1", "read"},
		{"data2_admin", "data2", "read"},
	},
	)
}

func TestNewAdapterWithInvalidURL(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected recovery from panic")
		}
	}()

	_, err := NewAdapter("localhost:40001?foo=1&bar=2")
	if err != nil {
		panic(err)
	}
}

func TestNewAdapterWithUnknownURL(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected recovery from panic")
		}
	}()

	_, err := NewAdapter("fakeserver:27017")
	if err != nil {
		panic(err)
	}
}

func TestNewAdapterWithDatabase(t *testing.T) {
	_, err := NewAdapter(fmt.Sprint(getDbURL() + "/abc"))
	if err != nil {
		panic(err)
	}
}
