package vault

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// Cross-language v2 fixture (74 bytes total, 62-byte payload). All values are
// synthetic. This literal is suitable for a future independent Swift encoder:
// key = ASCII "arbitrary/key" (13 bytes); fields in this exact order:
// login = ASCII "fixture-user" (12 bytes), token = 00 ff 42 (3 bytes).
// Header bytes 0..7 are MVLT/v2; bytes 8..11 are unsigned BE payload size 62.
const recordFrameGoldenHex = "4d564c54000000020000003e" +
	"0000000d6172626974726172792f6b6579" + // key length and key
	"00000002" + // field count
	"000000056c6f67696e0000000c666978747572652d75736572" + // login
	"00000005746f6b656e0000000300ff42" // token

func goldenRecordFrame(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(recordFrameGoldenHex)
	if err != nil || len(b) != 74 {
		t.Fatal("invalid synthetic golden fixture")
	}
	return b
}
func goldenRecordValues(t *testing.T) RecordValues {
	t.Helper()
	v, err := NewRecordValues([]byte("arbitrary/key"), [][2][]byte{
		{[]byte("login"), []byte("fixture-user")},
		{[]byte("token"), []byte{0, 255, 66}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func TestRecordFrameGoldenAndProtectedRoundTrip(t *testing.T) {
	golden := goldenRecordFrame(t)
	v := goldenRecordValues(t)
	var encoded bytes.Buffer
	if err := writeRecordFrame(&encoded, v); err != nil || !bytes.Equal(encoded.Bytes(), golden) {
		t.Fatal("v2 encoder differs from explicit cross-language fixture", err)
	}
	if err := writeRecordFrame(io.Discard, v); !errors.Is(err, ErrRecordFrame) {
		t.Fatal("encoder replay", err)
	}
	decoded, err := readRecordFrame(bytes.NewReader(golden))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(decoded); err == nil {
		t.Fatal("decoded record serialized")
	}
	for _, format := range []string{"%s", "%v", "%+v", "%#v", "%q"} {
		text := fmt.Sprintf(format, decoded)
		for _, private := range []string{"arbitrary/key", "login", "fixture-user", "token"} {
			if strings.Contains(text, private) {
				t.Fatal("decoded record printable")
			}
		}
	}
	var reencoded bytes.Buffer
	if err := writeRecordFrame(&reencoded, decoded); err != nil || !bytes.Equal(reencoded.Bytes(), golden) {
		t.Fatal("v2 decoder/encoder roundtrip", err)
	}
	if _, err := decoded.take(); !errors.Is(err, ErrRecord) {
		t.Fatal("decoded values not consumed")
	}
	if _, err := readNativeInput(bytes.NewReader(golden)); !errors.Is(err, ErrNativeInput) {
		t.Fatal("legacy decoder accepted v2")
	}
	if _, err := readRecordFrame(bytes.NewReader(fixtureNativeFrame([]byte("u"), []byte("p")))); !errors.Is(err, ErrRecordFrame) {
		t.Fatal("record decoder accepted legacy v1")
	}
}

// A deliberately retaining reader/writer lets tests verify that even the exact
// buffers passed across I/O boundaries are erased (normal adapters retain none).
type recordFrameReaderSpy struct {
	reader  io.Reader
	buffers [][]byte
	count   int
}

func (r *recordFrameReaderSpy) Read(p []byte) (int, error) {
	r.buffers = append(r.buffers, p)
	n, err := r.reader.Read(p)
	r.count += n
	return n, err
}
func assertFrameBuffersWiped(t *testing.T, buffers [][]byte) {
	t.Helper()
	for _, b := range buffers {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatal("frame I/O buffer retained data")
		}
	}
}
func TestRecordFrameDecoderRejectsMalformedAndWipesEveryRead(t *testing.T) {
	golden := goldenRecordFrame(t)
	cases := map[string][]byte{}
	for n := 0; n < len(golden); n++ {
		cases[fmt.Sprintf("truncate-%d", n)] = bytes.Clone(golden[:n])
	}
	for _, offset := range []int{8, 12, 29, 33, 42, 58, 67} {
		for _, length := range []uint32{0, 0xffffffff, 65536} {
			b := bytes.Clone(golden)
			binary.BigEndian.PutUint32(b[offset:offset+4], length)
			cases[fmt.Sprintf("length-%d-%d", offset, length)] = b
		}
	}
	for _, version := range []byte{0, 1, 3, 255} {
		b := bytes.Clone(golden)
		b[7] = version
		cases[fmt.Sprintf("version-%d", version)] = b
	}
	badMagic := bytes.Clone(golden)
	badMagic[0] ^= 1
	cases["magic"] = badMagic
	cases["trailing-byte"] = append(bytes.Clone(golden), 0x77)
	cases["second-frame"] = append(bytes.Clone(golden), golden...)
	duplicate := bytes.Clone(golden)
	copy(duplicate[62:67], "login")
	cases["duplicate-name"] = duplicate
	for name, frame := range cases {
		t.Run(name, func(t *testing.T) {
			spy := &recordFrameReaderSpy{reader: bytes.NewReader(frame)}
			v, err := readRecordFrame(spy)
			if !errors.Is(err, ErrRecordFrame) {
				v.Destroy()
				t.Fatal("malformed frame accepted", err)
			}
			assertFrameBuffersWiped(t, spy.buffers)
		})
	}
	spy := &recordFrameReaderSpy{reader: bytes.NewReader(golden)}
	v, err := readRecordFrame(spy)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Destroy()
	assertFrameBuffersWiped(t, spy.buffers)
	if _, err := readRecordFrame(nil); !errors.Is(err, ErrRecordFrame) {
		t.Fatal("nil reader accepted")
	}
}

type recordFrameWriterSpy struct {
	buffers [][]byte
	failAt  int
	short   bool
}

func (w *recordFrameWriterSpy) Write(p []byte) (int, error) {
	w.buffers = append(w.buffers, p)
	if len(w.buffers) == w.failAt {
		if w.short {
			return len(p) - 1, nil
		}
		return len(p) / 2, errors.New("synthetic-secret-transport-error")
	}
	return len(p), nil
}
func TestRecordFrameEncoderWipesValuesAndIOMemoryOnAllPaths(t *testing.T) {
	for _, test := range []struct {
		name   string
		writer *recordFrameWriterSpy
	}{
		{"success", &recordFrameWriterSpy{}},
		{"header-error", &recordFrameWriterSpy{failAt: 1}},
		{"payload-error", &recordFrameWriterSpy{failAt: 2}},
		{"header-short", &recordFrameWriterSpy{failAt: 1, short: true}},
		{"payload-short", &recordFrameWriterSpy{failAt: 2, short: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			key, name, secret := []byte("synthetic-key"), []byte("synthetic-name"), []byte("synthetic-secret")
			v, err := NewRecordValues(key, [][2][]byte{{name, secret}})
			if err != nil {
				t.Fatal(err)
			}
			err = writeRecordFrame(test.writer, v)
			if test.writer.failAt != 0 && !errors.Is(err, ErrRecordFrame) {
				t.Fatal("unsanitized encoder failure", err)
			}
			if test.writer.failAt == 0 && err != nil {
				t.Fatal(err)
			}
			assertFrameBuffersWiped(t, append(test.writer.buffers, key, name, secret))
			if _, err := v.take(); !errors.Is(err, ErrRecord) {
				t.Fatal("encoder did not consume values")
			}
		})
	}
	v := goldenRecordValues(t)
	if err := writeRecordFrame(nil, v); !errors.Is(err, ErrRecordFrame) {
		t.Fatal("nil writer accepted")
	}
	if _, err := v.take(); !errors.Is(err, ErrRecord) {
		t.Fatal("nil writer did not consume values")
	}
}
func TestRecordFrameCompleteSizeLimitAndEarlyOversizeRejection(t *testing.T) {
	// One-byte key and field name consume 18 payload bytes before the value.
	valueSize := maxRecordFrameBytes - recordFrameHeaderBytes - 18
	v, err := NewRecordValues([]byte("k"), [][2][]byte{{[]byte("n"), bytes.Repeat([]byte{0xff}, valueSize)}})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = writeRecordFrame(&out, v); err != nil || out.Len() != maxRecordFrameBytes {
		t.Fatal("exact size boundary", err)
	}
	decoded, err := readRecordFrame(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	decoded.Destroy()
	largeValue := bytes.Repeat([]byte{0xff}, valueSize+1)
	v, err = NewRecordValues([]byte("k"), [][2][]byte{{[]byte("n"), largeValue}})
	if err != nil {
		t.Fatal(err)
	}
	spy := &recordFrameWriterSpy{}
	if err = writeRecordFrame(spy, v); !errors.Is(err, ErrRecordFrame) || len(spy.buffers) != 0 {
		t.Fatal("oversize encoder wrote data", err)
	}
	assertFrameBuffersWiped(t, [][]byte{largeValue})
	for _, size := range []uint32{maxRecordFrameBytes - recordFrameHeaderBytes + 1, 0xffffffff} {
		frame := goldenRecordFrame(t)
		binary.BigEndian.PutUint32(frame[8:12], size)
		reader := &recordFrameReaderSpy{reader: bytes.NewReader(frame)}
		if _, err = readRecordFrame(reader); !errors.Is(err, ErrRecordFrame) || reader.count != recordFrameHeaderBytes {
			t.Fatal("oversize decoder read payload", err)
		}
		assertFrameBuffersWiped(t, reader.buffers)
	}
}

type recordFrameErrorAfterReader struct{ reader *bytes.Reader }

func (r recordFrameErrorAfterReader) Read(p []byte) (int, error) {
	if r.reader.Len() == 0 {
		return 0, errors.New("synthetic-secret-read-error")
	}
	return r.reader.Read(p)
}
func TestRecordFrameEOFRequiredAndErrorsSanitized(t *testing.T) {
	for _, size := range []int{5, 20, 74} {
		reader := &recordFrameReaderSpy{reader: recordFrameErrorAfterReader{reader: bytes.NewReader(goldenRecordFrame(t)[:size])}}
		if _, err := readRecordFrame(reader); err != ErrRecordFrame {
			t.Fatal("read error escaped", err)
		}
		assertFrameBuffersWiped(t, reader.buffers)
	}
}
func TestRecordFrameArbitraryBinaryKeyNameAndValue(t *testing.T) {
	v, err := NewRecordValues([]byte{0, 255, 1}, [][2][]byte{{[]byte{255, 0}, []byte{0, 128, 255}}})
	if err != nil {
		t.Fatal(err)
	}
	var first bytes.Buffer
	if err = writeRecordFrame(&first, v); err != nil {
		t.Fatal(err)
	}
	decoded, err := readRecordFrame(bytes.NewReader(first.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	var second bytes.Buffer
	if err = writeRecordFrame(&second, decoded); err != nil || !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("arbitrary bytes changed", err)
	}
}
