package mcp

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"math"
	"time"

	native "github.com/viant/mechanize/backend/darwin"
)

const (
	maximumPreviewSourcePixels    = 16_000_000 // PNG's worst-case RGBA64 decode is 128 MB.
	maximumPreviewSourceDimension = 16384
	maximumPreviewPixels          = 4_000_000
	maximumPreviewDimension       = 2560
	maximumPreviewLevels          = 4
	previewTimeout                = 5 * time.Second
)

// CapturePreview is a display derivative, never original pixel evidence or a
// business verification result. ScaleX/Y map its pixel coordinates to logical
// points: logicalX = Bounds.X + previewX*ScaleX (and likewise for Y).
// Image contains encoded binary bytes; base64 transport overhead is separate.
type CapturePreview struct {
	Image      []byte               `json:"-"`
	MimeType   string               `json:"mimeType,omitempty"`
	Width      int                  `json:"widthPixels,omitempty"`
	Height     int                  `json:"heightPixels,omitempty"`
	Available  bool                 `json:"available"`
	IsPreview  bool                 `json:"isPreview"`
	ScaleX     float64              `json:"scaleX,omitempty"`
	ScaleY     float64              `json:"scaleY,omitempty"`
	Bounds     native.CaptureBounds `json:"bounds"`
	Background string               `json:"background,omitempty"`
	Reason     string               `json:"reason,omitempty"`
}

var errPreviewByteBudget = errors.New("preview encoded byte budget exceeded")

// BuildCapturePreview preserves the full source and its artifact identity. It
// decodes at most 16M pixels, renders at most 4M pixels per level and attempts at
// most four PNG encodings plus four JPEG encodings. All work is synchronous;
// cancellation cannot leave a decoder/encoder goroutine consuming resources.
// Large sources beyond these memory budgets remain stored but have no preview.
func BuildCapturePreview(ctx context.Context, original []byte, metadata native.CaptureMetadata, maxEncodedBytes int) (CapturePreview, error) {
	out := CapturePreview{IsPreview: true, Bounds: metadata.Bounds}
	unavailable := func(reason string) (CapturePreview, error) { out.Reason = reason; return out, nil }
	if maxEncodedBytes <= 0 || maxEncodedBytes > MaximumInlineCaptureBytes {
		return out, errors.New("preview encoded byte budget must be 1...2 MiB")
	}
	ctx, cancel := context.WithTimeout(ctx, previewTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if len(original) == 0 || len(original) > native.MaximumCaptureBytes {
		return unavailable("Original image exceeds preview input byte budget")
	}
	finite := func(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }
	b := metadata.Bounds
	if metadata.Width <= 0 || metadata.Height <= 0 || metadata.Bytes != len(original) || metadata.CoordinateSpace != "globalLogicalPoints" || !finite(metadata.Scale) || metadata.Scale <= 0 || metadata.Scale > 16 || !finite(b.X) || !finite(b.Y) || !finite(b.Width) || !finite(b.Height) || b.Width <= 0 || b.Height <= 0 || math.Abs(b.Width*metadata.Scale-float64(metadata.Width)) > 1 || math.Abs(b.Height*metadata.Scale-float64(metadata.Height)) > 1 {
		return out, errors.New("preview source coordinate metadata invalid")
	}
	config, err := png.DecodeConfig(&previewReader{ctx: ctx, Reader: bytes.NewReader(original)})
	if err != nil {
		return out, previewContextError(ctx, err)
	}
	if config.Width != metadata.Width || config.Height != metadata.Height {
		return out, errors.New("preview PNG dimensions differ from source metadata")
	}
	if config.Width > maximumPreviewSourceDimension || config.Height > maximumPreviewSourceDimension || int64(config.Width)*int64(config.Height) > maximumPreviewSourcePixels {
		return unavailable("Original image exceeds preview decoder pixel or dimension budget")
	}
	source, err := png.Decode(&previewReader{ctx: ctx, Reader: bytes.NewReader(original)})
	if err != nil {
		return out, previewContextError(ctx, err)
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if len(original) <= maxEncodedBytes && config.Width <= maximumPreviewDimension && config.Height <= maximumPreviewDimension && config.Width*config.Height <= maximumPreviewPixels {
		out.Image = append([]byte(nil), original...)
		out.MimeType, out.Width, out.Height, out.Available = "image/png", config.Width, config.Height, true
		out.ScaleX, out.ScaleY = b.Width/float64(out.Width), b.Height/float64(out.Height)
		return out, nil
	}
	scale := math.Min(1, math.Min(float64(maximumPreviewDimension)/float64(config.Width), float64(maximumPreviewDimension)/float64(config.Height)))
	rasterBudget := maximumPreviewPixels
	if len(original) > maxEncodedBytes {
		// A large encoded source uses a display-only JPEG derivative. Cap its
		// initial encoder work to one pixel per output-budget byte, then retain
		// the existing adaptive reduction if encoding still exceeds that budget.
		// This work heuristic keeps whole-image/aspect/logical mapping intact;
		// actual encoded bytes, decoder/raster ceilings and the 5s deadline
		// remain independently checked. Original pixel evidence is unchanged.
		rasterBudget = min(rasterBudget, maxEncodedBytes)
	}
	scale = math.Min(scale, math.Sqrt(float64(rasterBudget)/(float64(config.Width)*float64(config.Height))))
	for level := 0; level < maximumPreviewLevels; level++ {
		width, height := max(1, int(math.Floor(float64(config.Width)*scale))), max(1, int(math.Floor(float64(config.Height)*scale)))
		// Integer raster dimensions introduce at most a pixel of rounding. Do
		// not distort extremely thin images where that rounding is material.
		if math.Abs((float64(width)/float64(height))/(float64(config.Width)/float64(config.Height))-1) > .01 {
			return unavailable("Preview aspect ratio cannot be preserved within bounded raster dimensions")
		}
		resized, resizeErr := resizePreview(ctx, source, width, height)
		if resizeErr != nil {
			return out, resizeErr
		}
		var encoded []byte
		var encodeErr error
		mime, background := "image/png", ""
		if len(original) <= maxEncodedBytes {
			encoded, encodeErr = encodePreview(ctx, resized, maxEncodedBytes, 0)
		} else {
			encodeErr = errPreviewByteBudget
		}
		if errors.Is(encodeErr, errPreviewByteBudget) {
			// JPEG is explicitly opaque. Composite premultiplied color on a
			// neutral RGB(240,240,240) background, retaining the whole image.
			if err = compositePreview(ctx, resized); err != nil {
				return out, err
			}
			// Quality 80 was already the bounded JPEG fallback. Selecting it
			// directly avoids re-encoding a raster whose higher-quality attempt
			// exceeds the same inline byte limit.
			encoded, encodeErr = encodePreview(ctx, resized, maxEncodedBytes, 80)
			mime, background = "image/jpeg", "#f0f0f0"
		}
		if encodeErr == nil {
			out.Image, out.MimeType, out.Width, out.Height, out.Available, out.Background = encoded, mime, width, height, true, background
			out.ScaleX, out.ScaleY = b.Width/float64(width), b.Height/float64(height)
			return out, nil
		}
		if !errors.Is(encodeErr, errPreviewByteBudget) {
			return out, previewContextError(ctx, encodeErr)
		}
		scale *= .75
	}
	return unavailable("Preview unavailable within bounded encoding work and byte budget; full original remains stored")
}

func previewContextError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

type previewReader struct {
	ctx context.Context
	io.Reader
}

func (r *previewReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	// Poll cancellation throughout compressed input consumption, including
	// highly compressible sources; pixel/dimension limits bound decode work.
	if len(data) > 1024 {
		data = data[:1024]
	}
	return r.Reader.Read(data)
}

type previewWriter struct {
	ctx  context.Context
	data []byte
	used int
}

func (w *previewWriter) Write(data []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if len(data) > len(w.data)-w.used {
		return 0, errPreviewByteBudget
	}
	copy(w.data[w.used:], data)
	w.used += len(data)
	return len(data), nil
}
func encodePreview(ctx context.Context, source image.Image, budget, jpegQuality int) ([]byte, error) {
	writer := &previewWriter{ctx: ctx, data: make([]byte, budget)}
	var err error
	if jpegQuality == 0 {
		encoder := png.Encoder{CompressionLevel: png.BestSpeed}
		err = encoder.Encode(writer, source)
	} else {
		err = jpeg.Encode(writer, source, &jpeg.Options{Quality: jpegQuality})
	}
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return writer.data[:writer.used:writer.used], nil
}

// resizePreview uses weighted area averaging for downsampling: it does not crop,
// stretch, sharpen or fabricate detail. Premultiplied RGBA preserves transparency.
func resizePreview(ctx context.Context, source image.Image, width, height int) (*image.RGBA, error) {
	result := image.NewRGBA(image.Rect(0, 0, width, height))
	bounds := source.Bounds()
	xSpans := previewAreaSpans(bounds.Dx(), width)
	ySpans := previewAreaSpans(bounds.Dy(), height)
	pixel := previewPixelReader(source)
	for y := 0; y < height; y++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		row := result.Pix[y*result.Stride : y*result.Stride+width*4]
		ySpan := ySpans[y]
		for x := 0; x < width; x++ {
			if x%128 == 0 {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
			}
			xSpan := xSpans[x]
			var red, green, blue, alpha, total float64
			for iy, wy := range ySpan.weights {
				for ix, wx := range xSpan.weights {
					weight := wy * wx
					r, g, b, a := pixel(xSpan.start+ix, ySpan.start+iy)
					red += float64(r) * weight
					green += float64(g) * weight
					blue += float64(b) * weight
					alpha += float64(a) * weight
					total += weight
				}
			}
			i := x * 4
			row[i], row[i+1], row[i+2], row[i+3] = uint8(math.Round(red/total/257)), uint8(math.Round(green/total/257)), uint8(math.Round(blue/total/257)), uint8(math.Round(alpha/total/257))
		}
	}
	return result, nil
}

type previewAreaSpan struct {
	start   int
	weights []float64
}

// Overlap weights depend only on their axis, not every output pixel. The
// accumulation order and floating-point operations match the original area
// filter, while avoiding millions of repeated bounds/overlap calculations.
func previewAreaSpans(source, target int) []previewAreaSpan {
	result := make([]previewAreaSpan, target)
	scale := float64(source) / float64(target)
	for index := range result {
		start, end := float64(index)*scale, float64(index+1)*scale
		first, last := int(start), int(math.Ceil(end))
		weights := make([]float64, last-first)
		for offset := range weights {
			position := first + offset
			weights[offset] = math.Min(end, float64(position+1)) - math.Max(start, float64(position))
		}
		result[index] = previewAreaSpan{start: first, weights: weights}
	}
	return result
}

// PNG commonly decodes to NRGBA. Calling Image.At boxes a color for every
// weighted sample, producing millions of short-lived allocations. Read common
// byte-backed images directly with the same 16-bit premultiplication as RGBA().
func previewPixelReader(source image.Image) func(int, int) (uint32, uint32, uint32, uint32) {
	bounds := source.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	switch pixels := source.(type) {
	case *image.NRGBA:
		return func(x, y int) (uint32, uint32, uint32, uint32) {
			if x < 0 || y < 0 || x >= width || y >= height {
				return 0, 0, 0, 0
			}
			i := y*pixels.Stride + x*4
			p := pixels.Pix[i : i+4 : i+4]
			a := uint32(p[3])
			return uint32(p[0]) * 257 * a / 255, uint32(p[1]) * 257 * a / 255, uint32(p[2]) * 257 * a / 255, a * 257
		}
	case *image.RGBA:
		return func(x, y int) (uint32, uint32, uint32, uint32) {
			if x < 0 || y < 0 || x >= width || y >= height {
				return 0, 0, 0, 0
			}
			i := y*pixels.Stride + x*4
			p := pixels.Pix[i : i+4 : i+4]
			return uint32(p[0]) * 257, uint32(p[1]) * 257, uint32(p[2]) * 257, uint32(p[3]) * 257
		}
	default:
		return func(x, y int) (uint32, uint32, uint32, uint32) {
			return source.At(bounds.Min.X+x, bounds.Min.Y+y).RGBA()
		}
	}
}
func compositePreview(ctx context.Context, source *image.RGBA) error {
	for y := 0; y < source.Rect.Dy(); y++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		row := source.Pix[y*source.Stride : y*source.Stride+source.Rect.Dx()*4]
		for i := 0; i < len(row); i += 4 {
			alpha := int(row[i+3])
			for channel := 0; channel < 3; channel++ {
				row[i+channel] = uint8(min(255, int(row[i+channel])+(240*(255-alpha)+127)/255))
			}
			row[i+3] = 255
		}
	}
	return nil
}
