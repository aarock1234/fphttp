package browser

func sourceCoverage() Coverage {
	return Coverage{
		TLS:     EvidenceSourceDerived,
		HTTP1:   EvidenceAssumed,
		HTTP2:   EvidenceSourceDerived,
		Headers: EvidenceSourceDerived,
	}
}

func assumedCoverage() Coverage {
	return Coverage{
		TLS:     EvidenceAssumed,
		HTTP1:   EvidenceAssumed,
		HTTP2:   EvidenceAssumed,
		Headers: EvidenceAssumed,
	}
}
