package app

// Payment card numbers (PANs). A bare 16-digit regex shreds timestamps and
// order IDs; requiring a card-network prefix, the right length for that
// network, a clean boundary and a Luhn mod-10 checksum removes nearly all of
// those. Single spaces or dashes between digits are allowed ("4111 1111 ...").

func luhnValid(d []byte, n int) bool {
	sum := 0
	dbl := false
	for i := n - 1; i >= 0; i-- {
		v := int(d[i])
		if dbl {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
		dbl = !dbl
	}
	return sum%10 == 0
}

func panNetworkOK(d []byte, n int) bool {
	if n < 13 || n > 19 {
		return false
	}
	p2 := int(d[0])*10 + int(d[1])
	p4 := p2*100 + int(d[2])*10 + int(d[3])
	switch {
	case d[0] == 4: // Visa
		return n == 13 || n == 16 || n == 19
	case p2 >= 51 && p2 <= 55, p4 >= 2221 && p4 <= 2720: // Mastercard
		return n == 16
	case p2 == 34 || p2 == 37: // American Express
		return n == 15
	case p4 == 6011, p2 == 65: // Discover
		return n >= 16 && n <= 19
	}
	return false
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func (s *Scrubber) scrubPANs(in string) (string, int) {
	spans := panSpans(in)
	if len(spans) == 0 {
		return in, 0
	}
	b := make([]byte, 0, len(in)+32)
	last := 0
	for _, sp := range spans {
		b = append(b, in[last:sp.start]...)
		b = append(b, s.tag("PAN", in[sp.start:sp.end])...)
		s.Tokens.Add(1)
		last = sp.end
	}
	b = append(b, in[last:]...)
	return string(b), len(spans)
}

// panSpans returns where payment card numbers sit in in. It allocates only
// when it finds one.
func panSpans(in string) []secretSpan {
	if len(in) < 13 {
		return nil
	}
	var spans []secretSpan
	var d [20]byte
	for i := 0; i < len(in); {
		if !isDigit(in[i]) {
			i++
			continue
		}
		// first contiguous digit run, used to resume after a failed candidate
		k := i
		for k < len(in) && isDigit(in[k]) {
			k++
		}
		if i > 0 {
			p := in[i-1]
			if isWordByte(p) || (p == '.' && i > 1 && isDigit(in[i-2])) {
				i = k
				continue
			}
		}
		nd, j, end, over := 0, i, i, false
		for j < len(in) {
			c := in[j]
			if isDigit(c) {
				if nd == len(d)-1 {
					over = true
					break
				}
				d[nd] = c - '0'
				nd++
				j++
				end = j
				continue
			}
			if (c == ' ' || c == '-') && nd > 0 && j+1 < len(in) && isDigit(in[j+1]) {
				j++
				continue
			}
			break
		}
		ok := !over && panNetworkOK(d[:], nd) && luhnValid(d[:], nd)
		if ok && end < len(in) {
			nx := in[end]
			if isWordByte(nx) || (nx == '.' && end+1 < len(in) && isDigit(in[end+1])) {
				ok = false
			}
		}
		if !ok {
			i = k
			continue
		}
		spans = append(spans, secretSpan{start: i, end: end})
		i = end
	}
	return spans
}
