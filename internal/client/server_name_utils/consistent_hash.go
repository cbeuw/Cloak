/*
 * Copyright (c) 2025. Proton AG
 *
 * This file is part of ProtonVPN.
 *
 * ProtonVPN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ProtonVPN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
 */

package server_name_utils

import (
	"hash/crc32"
	"math"
	"sort"
)

// Set of utilities to implement consistent hashing where map one set of strings (keys) to another (values).
// Set of values will change over time but mapping will remain largely stable.
// Usage:
// hashedValues := sortValuesByHash(values, crc32Hash)
// value := findClosestValue(key, hashedValues, crc32Hash)
// when set of values changes (e.g. new one is added), only mappings that will change are for keys for which
// new value is the closest one (its uint32 hash is closest to key's hash).

type HashedValue struct {
	value string
	hash  uint32
}

// Picks value out of sortedValuesWithHashes which hash is closest to hash of value. For distance
// calculation, uint32 is forming a ring where 0 is next to math.MaxUint32. Closer of clockwise and
// counter-clockwise distance is picked.
func findClosestValue(key string, sortedValuesWithHashes []HashedValue, hashFun func(string) uint32) string {
	n := len(sortedValuesWithHashes)
	if n == 0 {
		return ""
	} else if n == 1 {
		return sortedValuesWithHashes[0].value
	}

	keyHash := hashFun(key)
	i := sort.Search(n, func(i int) bool {
		return sortedValuesWithHashes[i].hash >= keyHash
	})

	if i <= 0 || i >= n {
		// If it's smaller than first or larger than last, return closest
		// between first and last
		return closerValue(keyHash, sortedValuesWithHashes[0], sortedValuesWithHashes[n-1])
	} else {
		return closerValue(keyHash, sortedValuesWithHashes[i-1], sortedValuesWithHashes[i])
	}
}

func sortValuesByHash(values []string, hashFun func(string) uint32) []HashedValue {
	hashedValues := make([]HashedValue, len(values))
	for i, domain := range values {
		hashedValues[i] = HashedValue{domain, hashFun(domain)}
	}
	sort.Slice(hashedValues, func(i, j int) bool {
		return hashedValues[i].hash < hashedValues[j].hash
	})
	return hashedValues
}

func crc32Hash(s string) uint32 {
	return crc32.ChecksumIEEE([]byte(s))
}

func ringDistance(a, b uint32) int64 {
	var fa = int64(a)
	var fb = int64(b)
	var large = max(fa, fb)
	var small = min(fa, fb)
	// Take smaller of clockwise and counter-clockwise distance
	return min(large-small, small-large+math.MaxUint32)
}

func closerValue(hash uint32, a HashedValue, b HashedValue) string {
	var da = ringDistance(hash, a.hash)
	var db = ringDistance(hash, b.hash)
	if da < db {
		return a.value
	} else {
		return b.value
	}
}
