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

	"github.com/ing-bank/zkrp/util/intconversion"
)

/*
Test method VectorCopy, which simply copies the first input argument to size n vector.
*/
func TestVectorCopy(t *testing.T) {
	var (
		result []*big.Int
	)
	result, _ = VectorCopy(big.NewInt(1), 3)
	ok := result[0].Cmp(big.NewInt(1)) == 0
	ok = ok && (result[1].Cmp(big.NewInt(1)) == 0)
	ok = ok && (result[2].Cmp(big.NewInt(1)) == 0)
	if ok != true {
		t.Errorf("Assert failure: expected true, actual: %t", ok)
	}
}

/*
Test method VectorConvertToBig.
*/
func TestVectorConvertToBig(t *testing.T) {
	var (
		result []*big.Int
		a      []int64
	)
	a = make([]int64, 3)
	a[0] = 3
	a[1] = 4
	a[2] = 5
	result, _ = VectorConvertToBig(a, 3)
	ok := result[0].Cmp(big.NewInt(3)) == 0
	ok = ok && (result[1].Cmp(big.NewInt(4)) == 0)
	ok = ok && (result[2].Cmp(big.NewInt(5)) == 0)
	if ok != true {
		t.Errorf("Assert failure: expected true, actual: %t", ok)
	}
}

/*
Tests Vector addition.
*/
func TestVectorAdd(t *testing.T) {
	var (
		a, b []*big.Int
	)
	var SecP256k1Group = group.NewSecP256k1Group()

	a = make([]*big.Int, 3)
	b = make([]*big.Int, 3)
	a[0] = new(big.Int).SetInt64(7)
	a[1] = new(big.Int).SetInt64(8)
	a[2] = new(big.Int).SetInt64(9)
	b[0] = new(big.Int).SetInt64(3)
	b[1] = new(big.Int).SetInt64(30)
	b[2] = new(big.Int).SetInt64(40)
	result, _ := VectorAdd(a, b, SecP256k1Group.N())
	ok := result[0].Cmp(new(big.Int).SetInt64(10)) == 0
	ok = ok && (result[1].Cmp(intconversion.BigFromBase10("38")) == 0)
	ok = ok && (result[2].Cmp(intconversion.BigFromBase10("49")) == 0)
	if ok != true {
		t.Errorf("Assert failure: expected true, actual: %t", ok)
	}
}

/*
Tests Vector subtraction.
*/
func TestVectorSub(t *testing.T) {
	var (
		a, b []*big.Int
	)
	var SecP256k1Group = group.NewSecP256k1Group()

	a = make([]*big.Int, 3)
	b = make([]*big.Int, 3)
	a[0] = new(big.Int).SetInt64(7)
	a[1] = new(big.Int).SetInt64(8)
	a[2] = new(big.Int).SetInt64(9)
	b[0] = new(big.Int).SetInt64(3)
	b[1] = new(big.Int).SetInt64(30)
	b[2] = new(big.Int).SetInt64(40)
	result, _ := VectorSub(a, b, SecP256k1Group.N())
	ok := result[0].Cmp(new(big.Int).SetInt64(4)) == 0
	ok = ok && (result[1].Cmp(intconversion.BigFromBase10("115792089237316195423570985008687907852837564279074904382605163141518161494315")) == 0)
	ok = ok && (result[2].Cmp(intconversion.BigFromBase10("115792089237316195423570985008687907852837564279074904382605163141518161494306")) == 0)
	if ok != true {
		t.Errorf("Assert failure: expected true, actual: %t", ok)
	}
}

/*
Tests Vector componentwise multiplication.
*/
func TestVectorMul(t *testing.T) {
	var (
		a, b []*big.Int
	)
	var SecP256k1Group = group.NewSecP256k1Group()

	a = make([]*big.Int, 3)
	b = make([]*big.Int, 3)
	a[0] = new(big.Int).SetInt64(7)
	a[1] = new(big.Int).SetInt64(8)
	a[2] = new(big.Int).SetInt64(9)
	b[0] = new(big.Int).SetInt64(3)
	b[1] = new(big.Int).SetInt64(30)
	b[2] = new(big.Int).SetInt64(40)
	result, _ := VectorMul(a, b, SecP256k1Group.N())
	ok := result[0].Cmp(new(big.Int).SetInt64(21)) == 0
	ok = ok && (result[1].Cmp(new(big.Int).SetInt64(240)) == 0)
	ok = ok && (result[2].Cmp(new(big.Int).SetInt64(360)) == 0)

	if ok != true {
		t.Errorf("Assert failure: expected true, actual: %t", ok)
	}
}
