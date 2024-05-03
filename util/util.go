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

package util

import (
	"github.com/takakv/msc-poc/group"
	"math/big"
)

/*
Decompose receives as input a bigint x and outputs an array of integers such that
x = sum(xi.u^i), i.e. it returns the decomposition of x into base u.
*/
func Decompose(x *big.Int, u int64, l int64) []int64 {
	result := make([]int64, l)

	for i := int64(0); i < l; i++ {
		result[i] = new(big.Int).Mod(x, new(big.Int).SetInt64(u)).Int64()
		x = new(big.Int).Div(x, new(big.Int).SetInt64(u))
	}

	return result
}

// PedersenCommit creates a commitment to secret x using randomness r in group GP.
func PedersenCommit(x, r *big.Int, h group.Element, GP group.Group) group.Element {
	C := GP.Element().BaseScale(x)
	Hr := GP.Element().Scale(h, r)
	C = GP.Element().Add(C, Hr)
	return C
}
