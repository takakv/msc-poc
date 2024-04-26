/*
 * Copyright (C) 2019 ING BANK N.V.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package bulletproofs

import (
	"github.com/takakv/msc-poc/group"
	"math/big"
	"testing"
)

/*
Test Inner Product argument where <a,b>=c.
*/
func TestInnerProduct(t *testing.T) {
	var (
		a []*big.Int
		b []*big.Int
	)
	c := new(big.Int).SetInt64(142)

	var SecP256k1Group = group.SecP256k1()

	innerProductParams, _ := setupInnerProduct(nil, nil, nil, c, 4, SecP256k1Group)

	a = make([]*big.Int, innerProductParams.N)
	a[0] = new(big.Int).SetInt64(2)
	a[1] = new(big.Int).SetInt64(-1)
	a[2] = new(big.Int).SetInt64(10)
	a[3] = new(big.Int).SetInt64(6)
	b = make([]*big.Int, innerProductParams.N)
	b[0] = new(big.Int).SetInt64(1)
	b[1] = new(big.Int).SetInt64(2)
	b[2] = new(big.Int).SetInt64(10)
	b[3] = new(big.Int).SetInt64(7)

	commit := commitInnerProduct(innerProductParams.Gg, innerProductParams.Hh, a, b, innerProductParams.SP)

	proof, _ := proveInnerProduct(a, b, commit, innerProductParams)
	ok, _ := proof.Verify()
	if ok != true {
		t.Errorf("Assert failure: expected true, actual: %t", ok)
	}
}
