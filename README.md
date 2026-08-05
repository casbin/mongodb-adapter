<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements. See the NOTICE file
distributed with this work for additional information
regarding copyright ownership. The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License. You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the
specific language governing permissions and limitations
under the License.
-->

MongoDB Adapter
====

[![Go Report Card](https://goreportcard.com/badge/github.com/apache/casbin-mongodb-adapter)](https://goreportcard.com/report/github.com/apache/casbin-mongodb-adapter)
[![Build](https://github.com/apache/casbin-mongodb-adapter/actions/workflows/ci.yml/badge.svg)](https://github.com/apache/casbin-mongodb-adapter/actions/workflows/ci.yml)
[![Godoc](https://godoc.org/github.com/apache/casbin-mongodb-adapter?status.svg)](https://pkg.go.dev/github.com/casbin/mongodb-adapter/v4)
[![Release](https://img.shields.io/github/release/apache/casbin-mongodb-adapter.svg)](https://github.com/apache/casbin-mongodb-adapter/releases/latest)
[![Discord](https://img.shields.io/discord/1022748306096537660?logo=discord&label=discord&color=5865F2)](https://discord.gg/S5UjpzGZjN)
[![Sourcegraph](https://sourcegraph.com/github.com/apache/casbin-mongodb-adapter/-/badge.svg)](https://sourcegraph.com/github.com/apache/casbin-mongodb-adapter?badge)

MongoDB Adapter is the [Mongo DB](https://www.mongodb.com) adapter for [Casbin](https://github.com/casbin/casbin). With this library, Casbin can load policy from MongoDB or save policy to it.

## Installation

    go get -u github.com/casbin/mongodb-adapter/v4

## Simple Example

```go
package main

import (
	"github.com/casbin/casbin/v2"
	"github.com/casbin/mongodb-adapter/v4"
)

func main() {
	// Initialize a MongoDB adapter and use it in a Casbin enforcer:
	// The adapter will use the database named "casbin".
	// If it doesn't exist, the adapter will create it automatically.
	a,err := mongodbadapter.NewAdapter("127.0.0.1:27017") // Your MongoDB URL. 
	if err != nil {
		panic(err)
	}
	// Or you can use an existing DB "abc" like this:
	// The adapter will use the table named "casbin_rule".
	// If it doesn't exist, the adapter will create it automatically.
	// a := mongodbadapter.NewAdapter("127.0.0.1:27017/abc")

	e, err := casbin.NewEnforcer("examples/rbac_model.conf", a)
	if err != nil {
		panic(err)
	}

	// Load the policy from DB.
	e.LoadPolicy()
	
	// Check the permission.
	e.Enforce("alice", "data1", "read")
	
	// Modify the policy.
	// e.AddPolicy(...)
	// e.RemovePolicy(...)
	
	// Save the policy back to DB.
	e.SavePolicy()
}
```
## Advanced Example

```go
package main

import (
	"github.com/casbin/casbin/v2"
	"github.com/casbin/mongodb-adapter/v4"
	mongooptions "go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	// Initialize a MongoDB adapter with NewAdapterWithClientOption:
	// The adapter will use custom mongo client options.
	// custom database name.
	// default collection name 'casbin_rule'.
	mongoClientOption := mongooptions.Client().ApplyURI("mongodb://127.0.0.1:27017")
	databaseName := "casbin"
	a,err := mongodbadapter.NewAdapterWithClientOption(mongoClientOption, databaseName)
	// Or you can use NewAdapterWithCollectionName for custom collection name.
	if err != nil {
		panic(err)
	}

	e, err := casbin.NewEnforcer("examples/rbac_model.conf", a)
	if err != nil {
		panic(err)
	}

	// Load the policy from DB.
	e.LoadPolicy()
	
	// Check the permission.
	e.Enforce("alice", "data1", "read")
	
	// Modify the policy.
	// e.AddPolicy(...)
	// e.RemovePolicy(...)
	
	// Save the policy back to DB.
	e.SavePolicy()
}
```

## Filtered Policies

```go
import "github.com/globalsign/mgo/bson"

// This adapter also implements the FilteredAdapter interface. This allows for
// efficent, scalable enforcement of very large policies:
filter := &bson.M{"v0": "alice"}
e.LoadFilteredPolicy(filter)

// The loaded policy is now a subset of the policy in storage, containing only
// the policy lines that match the provided filter. This filter should be a
// valid MongoDB selector using BSON. A filtered policy cannot be saved.
```

## Getting Help

- [Casbin](https://github.com/casbin/casbin)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.
