package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"math"
	"testing"
	"time"

	native "github.com/viant/mechanize/backend/darwin"
)

func previewFixture(t *testing.T, width, height int, transparent bool) ([]byte, native.CaptureMetadata) {
	t.Helper()
	source := image.NewNRGBA(image.Rect(0, 0, width, height))
	state := uint32(42)
	for i := 0; i < len(source.Pix); i += 4 {
		for channel := 0; channel < 3; channel++ {
			state ^= state << 13
			state ^= state >> 17
			state ^= state << 5
			source.Pix[i+channel] = byte(state)
		}
		source.Pix[i+3] = 255
	}
	if transparent {
		for y := 0; y < min(100, height); y++ {
			for x := 0; x < min(100, width); x++ {
				source.SetNRGBA(x, y, color.NRGBA{R: 255, A: 0})
			}
		}
	}
	var data bytes.Buffer
	encoder := png.Encoder{CompressionLevel: png.BestSpeed}
	if err := encoder.Encode(&data, source); err != nil {
		t.Fatal(err)
	}
	metadata := native.CaptureMetadata{Width: width, Height: height, Bytes: data.Len(), Scale: 2, CoordinateSpace: "globalLogicalPoints", Bounds: native.CaptureBounds{X: -600, Y: -250, Width: float64(width) / 2, Height: float64(height) / 2}}
	return data.Bytes(), metadata
}

func TestCapturePreviewLargeDeterministicBoundedMapping(t *testing.T) {
	original, metadata := previewFixture(t, 2800, 1700, true)
	if len(original) <= MaximumInlineCaptureBytes {
		t.Fatal("fixture is not a large encoded image")
	}
	hash := sha256.Sum256(original)
	started := time.Now()
	first, err := BuildCapturePreview(context.Background(), original, metadata, MaximumInlineCaptureBytes)
	t.Logf("first preview processing: %s", time.Since(started))
	if err != nil {
		t.Fatal(err)
	}
	if !first.Available || !first.IsPreview || first.MimeType != "image/jpeg" || first.Background != "#f0f0f0" || len(first.Image) > MaximumInlineCaptureBytes || first.Width > maximumPreviewDimension || first.Height > maximumPreviewDimension || first.Width*first.Height > maximumPreviewPixels {
		t.Fatalf("invalid preview: %+v bytes=%d", first, len(first.Image))
	}
	if first.Width >= metadata.Width || first.Height >= metadata.Height {
		t.Fatal("large source did not exercise bounded downsampling")
	}
	if first.Bounds != metadata.Bounds || first.ScaleX != metadata.Bounds.Width/float64(first.Width) || first.ScaleY != metadata.Bounds.Height/float64(first.Height) {
		t.Fatal("preview lost logical coordinate mapping")
	}
	if math.Abs(float64(first.Width)-float64(first.Height)*float64(metadata.Width)/float64(metadata.Height)) > 1+float64(metadata.Width)/float64(metadata.Height) {
		t.Fatal("aspect changed beyond raster rounding")
	}
	decoded, err := jpeg.Decode(bytes.NewReader(first.Image))
	if err != nil || decoded.Bounds().Dx() != first.Width || decoded.Bounds().Dy() != first.Height {
		t.Fatalf("preview dimensions: %v", err)
	}
	r, g, b, a := decoded.At(10, 10).RGBA()
	for _, channel := range []uint32{r, g, b} {
		if math.Abs(float64(channel/257)-240) > 3 {
			t.Fatal("transparent pixels not composited on neutral background")
		}
	}
	if a != 65535 {
		t.Fatal("JPEG preview not opaque")
	}
	started = time.Now()
	second, err := BuildCapturePreview(context.Background(), original, metadata, MaximumInlineCaptureBytes)
	t.Logf("second preview processing: %s; raster %dx%d; encoded %d bytes", time.Since(started), first.Width, first.Height, len(first.Image))
	if err != nil || !bytes.Equal(first.Image, second.Image) || first.Width != second.Width || first.Height != second.Height {
		t.Fatalf("preview not deterministic: %v", err)
	}
	if sha256.Sum256(original) != hash {
		t.Fatal("original evidence changed")
	}
}

func TestCapturePreviewBoundsAndCancellation(t *testing.T) {
	original, metadata := previewFixture(t, 64, 32, false)
	preview, err := BuildCapturePreview(context.Background(), original, metadata, MaximumInlineCaptureBytes)
	if err != nil || !preview.Available || preview.MimeType != "image/png" || !bytes.Equal(preview.Image, original) {
		t.Fatalf("small preview: %v %+v", err, preview)
	}
	preview.Image[0] = 0
	if original[0] != 137 {
		t.Fatal("preview aliases original evidence bytes")
	}
	for _, budget := range []int{0, -1, MaximumInlineCaptureBytes + 1} {
		if _, err = BuildCapturePreview(context.Background(), original, metadata, budget); err == nil {
			t.Fatalf("invalid budget%d accepted", budget)
		}
	}
	bad := metadata
	bad.Bounds.Width = math.Inf(1)
	if _, err = BuildCapturePreview(context.Background(), original, bad, 100); err == nil {
		t.Fatal("nonfinite bounds accepted")
	}
	bad = metadata
	bad.Width++
	if _, err = BuildCapturePreview(context.Background(), original, bad, 100); err == nil {
		t.Fatal("mismatched dimensions accepted")
	}
	malformed := append([]byte(nil), original[:len(original)/2]...)
	bad = metadata
	bad.Bytes = len(malformed)
	if _, err = BuildCapturePreview(context.Background(), malformed, bad, 100); err == nil {
		t.Fatal("truncated PNG accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = BuildCapturePreview(ctx, original, metadata, 100); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err = BuildCapturePreview(ctx, original, metadata, 100); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
	unavailable, err := BuildCapturePreview(context.Background(), original, metadata, 1)
	if err != nil || unavailable.Available || len(unavailable.Image) != 0 || unavailable.Reason == "" || !unavailable.IsPreview {
		t.Fatalf("tiny budget not unavailable: %+v %v", unavailable, err)
	}
}

func TestCapturePreviewDecoderBudgetBeforeAllocation(t *testing.T) {
	original, metadata := previewFixture(t, 2, 2, false)
	for _, size := range [][2]int{{4001, 4000}, {maximumPreviewSourceDimension + 1, 1}} {
		// A valid IHDR with hostile dimensions must be rejected before pixel
		// decoding, even though the source body contains only a tiny image.
		hostile := append([]byte(nil), original...)
		binary.BigEndian.PutUint32(hostile[16:20], uint32(size[0]))
		binary.BigEndian.PutUint32(hostile[20:24], uint32(size[1]))
		binary.BigEndian.PutUint32(hostile[29:33], crc32.ChecksumIEEE(hostile[12:29]))
		bad := metadata
		bad.Width, bad.Height = size[0], size[1]
		bad.Bounds.Width, bad.Bounds.Height = float64(size[0])/2, float64(size[1])/2
		preview, err := BuildCapturePreview(context.Background(), hostile, bad, MaximumInlineCaptureBytes)
		if err != nil || preview.Available || preview.Reason == "" {
			t.Fatalf("decoder budget not enforced: %+v %v", preview, err)
		}
	}
	oversized := make([]byte, native.MaximumCaptureBytes+1)
	preview, err := BuildCapturePreview(context.Background(), oversized, metadata, MaximumInlineCaptureBytes)
	if err != nil || preview.Available || preview.Reason == "" {
		t.Fatal("input byte budget not enforced")
	}
}

func TestPreviewReadersWritersHonorCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader := previewReader{ctx: ctx, Reader: bytes.NewReader([]byte("fixture"))}
	if _, err := reader.Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatal("decoder reader ignored cancel")
	}
	writer := previewWriter{ctx: ctx, data: make([]byte, 10)}
	if _, err := writer.Write([]byte("fixture")); !errors.Is(err, context.Canceled) {
		t.Fatal("encoder writer ignored cancel")
	}
	writer = previewWriter{ctx: context.Background(), data: make([]byte, 3)}
	if _, err := writer.Write([]byte("fixture")); !errors.Is(err, errPreviewByteBudget) || writer.used != 0 {
		t.Fatal("encoder allocated past byte limit")
	}
}

func TestCapturePreviewCompressibleImageStillBoundsDimensions(t *testing.T) {
	for _, dimensions := range [][2]int{{3000, 1000}, {1, 10000}} {
		var encoded bytes.Buffer
		if err := png.Encode(&encoded, image.NewRGBA(image.Rect(0, 0, dimensions[0], dimensions[1]))); err != nil {
			t.Fatal(err)
		}
		metadata := native.CaptureMetadata{Width: dimensions[0], Height: dimensions[1], Bytes: encoded.Len(), Scale: 1, CoordinateSpace: "globalLogicalPoints", Bounds: native.CaptureBounds{Width: float64(dimensions[0]), Height: float64(dimensions[1])}}
		preview, err := BuildCapturePreview(context.Background(), encoded.Bytes(), metadata, MaximumInlineCaptureBytes)
		if err != nil {
			t.Fatal(err)
		}
		if dimensions[0] == 1 {
			if preview.Available || preview.Reason == "" {
				t.Fatal("thin frame distorted instead of unavailable")
			}
			continue
		}
		if !preview.Available || preview.Width > maximumPreviewDimension || preview.Height > maximumPreviewDimension || preview.Width*preview.Height > maximumPreviewPixels {
			t.Fatal("compressible image bypassed output raster budget")
		}
	}
}
