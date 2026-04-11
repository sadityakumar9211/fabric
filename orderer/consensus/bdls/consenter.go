/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdls

import (
	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/hyperledger/fabric-lib-go/common/metrics"
)

// ---------------------------------------------------------------------------
// This file is a scaffold. The full Consenter / HandleChain / IsChannelMember
// implementation lands in a later commit (Phase C7). For now we only need:
//
//   * a type named Consenter that future commits will grow methods on, and
//   * a New constructor that carries a FabricLogger, a Metrics bundle, and
//     the BCCSP — the three dependencies every later file will reach for.
//
// Nothing in this file is wired into orderer/common/server/main.go yet, so
// dropping this package into the tree has zero runtime effect.
// ---------------------------------------------------------------------------

// Consenter is the BDLS implementation of consensus.Consenter. Its zero value
// is not usable — always construct via newConsenterFromMetrics.
type Consenter struct {
	Logger  *flogging.FabricLogger
	Metrics *Metrics
	BCCSP   bccsp.BCCSP
}

// newConsenterFromMetrics is the core constructor used by tests and (later)
// by the public New. Kept unexported for now so the scaffold commit does not
// pretend to offer a stable public API.
func newConsenterFromMetrics(provider metrics.Provider, csp bccsp.BCCSP) *Consenter {
	return &Consenter{
		Logger:  flogging.MustGetLogger("orderer.consensus.bdls"),
		Metrics: NewMetrics(provider),
		BCCSP:   csp,
	}
}
