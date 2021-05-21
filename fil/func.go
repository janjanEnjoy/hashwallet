package fil

func coinType() uint32 {
	if TEST {
		return tCoinID
	} else {
		return coinID
	}
}
