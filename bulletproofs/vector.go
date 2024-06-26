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
	"errors"
	"github.com/takakv/msc-poc/group"
	"math/big"

	"github.com/ing-bank/zkrp/util/bn"
)

/*
VectorCopy returns a vector composed by copies of a.
*/
func VectorCopy(a *big.Int, n int64) ([]*big.Int, error) {
	var (
		i      int64
		result []*big.Int
	)
	result = make([]*big.Int, n)
	i = 0
	for i < n {
		result[i] = a
		i = i + 1
	}
	return result, nil
}

/*
VectorConvertToBig converts an array of int64 to an array of big.Int.
*/
func VectorConvertToBig(a []int64, n int64) ([]*big.Int, error) {
	var (
		i      int64
		result []*big.Int
	)
	result = make([]*big.Int, n)
	i = 0
	for i < n {
		result[i] = new(big.Int).SetInt64(a[i])
		i = i + 1
	}
	return result, nil
}

/*
VectorAdd computes vector addition componentwisely.
*/
func VectorAdd(a, b []*big.Int, mod *big.Int) ([]*big.Int, error) {
	var (
		result  []*big.Int
		i, n, m int64
	)
	n = int64(len(a))
	m = int64(len(b))
	if n != m {
		return nil, errors.New("Size of first argument is different from size of second argument.")
	}
	i = 0
	result = make([]*big.Int, n)
	for i < n {
		result[i] = bn.Add(a[i], b[i])
		result[i] = bn.Mod(result[i], mod)
		i = i + 1
	}
	return result, nil
}

/*
VectorSub computes vector addition componentwisely.
*/
func VectorSub(a, b []*big.Int, mod *big.Int) ([]*big.Int, error) {
	var (
		result  []*big.Int
		i, n, m int64
	)
	n = int64(len(a))
	m = int64(len(b))
	if n != m {
		return nil, errors.New("Size of first argument is different from size of second argument.")
	}
	i = 0
	result = make([]*big.Int, n)
	for i < n {
		result[i] = bn.Sub(a[i], b[i])
		result[i] = bn.Mod(result[i], mod)
		i = i + 1
	}
	return result, nil
}

func VectorAddConst(a []*big.Int, c *big.Int, mod *big.Int) []*big.Int {
	result := make([]*big.Int, len(a))
	for i := range result {
		result[i] = new(big.Int).Add(a[i], c)
		result[i].Mod(result[i], mod)
	}
	return result
}

/*
VectorScalarMul computes vector scalar multiplication componentwisely.
*/
func VectorScalarMul(a []*big.Int, b *big.Int, mod *big.Int) ([]*big.Int, error) {
	var (
		result []*big.Int
		i, n   int64
	)
	n = int64(len(a))
	i = 0
	result = make([]*big.Int, n)
	for i < n {
		result[i] = bn.Multiply(a[i], b)
		result[i] = bn.Mod(result[i], mod)
		i = i + 1
	}
	return result, nil
}

/*
VectorMul computes vector multiplication componentwisely.
*/
func VectorMul(a, b []*big.Int, mod *big.Int) ([]*big.Int, error) {
	var (
		result  []*big.Int
		i, n, m int64
	)
	n = int64(len(a))
	m = int64(len(b))
	if n != m {
		return nil, errors.New("Size of first argument is different from size of second argument.")
	}
	i = 0
	result = make([]*big.Int, n)
	for i < n {
		result[i] = bn.Multiply(a[i], b[i])
		result[i] = bn.Mod(result[i], mod)
		i = i + 1
	}
	return result, nil
}

func VectorInnerProduct(a, b []*big.Int, mod *big.Int) *big.Int {
	result := big.NewInt(0)
	for i := range a {
		tmp := new(big.Int).Mul(a[i], b[i])
		result.Add(result, tmp.Mod(tmp, mod))
	}
	result.Mod(result, mod)
	return result
}

/*
VectorECMul computes vector EC addition componentwisely.
*/
func VectorECAdd(a, b []group.Element, SP group.Group) ([]group.Element, error) {
	var (
		result  []group.Element
		i, n, m int64
	)
	n = int64(len(a))
	m = int64(len(b))
	if n != m {
		return nil, errors.New("Size of first argument is different from size of second argument.")
	}
	result = make([]group.Element, n)
	i = 0
	for i < n {
		// result[i] = new(p256.P256).Multiply(a[i], b[i])
		result[i] = SP.Element().Add(a[i], b[i])
		i = i + 1
	}
	return result, nil
}
