package mcp

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/draw"
	"math"
	"testing"
)

// Independent direct area integration reference retains the original generic
// Image.At/RGBA path. Compare exact pixels, not only encoded metadata or hashes.
func referencePreviewArea(source image.Image, width, height int) *image.RGBA {
	result := image.NewRGBA(image.Rect(0, 0, width, height))
	bounds := source.Bounds()
	sx, sy := float64(bounds.Dx())/float64(width), float64(bounds.Dy())/float64(height)
	for y := 0; y < height; y++ {
		y0, y1 := float64(y)*sy, float64(y+1)*sy
		for x := 0; x < width; x++ {
			x0, x1 := float64(x)*sx, float64(x+1)*sx
			var r, g, b, a, total float64
			for iy := int(y0); iy < int(math.Ceil(y1)); iy++ {
				wy := math.Min(y1, float64(iy+1)) - math.Max(y0, float64(iy))
				for ix := int(x0); ix < int(math.Ceil(x1)); ix++ {
					weight := wy * (math.Min(x1, float64(ix+1)) - math.Max(x0, float64(ix)))
					cr, cg, cb, ca := source.At(bounds.Min.X+ix, bounds.Min.Y+iy).RGBA()
					r += float64(cr) * weight
					g += float64(cg) * weight
					b += float64(cb) * weight
					a += float64(ca) * weight
					total += weight
				}
			}
			result.SetRGBA(x, y, color.RGBA{R: uint8(math.Round(r / total / 257)), G: uint8(math.Round(g / total / 257)), B: uint8(math.Round(b / total / 257)), A: uint8(math.Round(a / total / 257))})
		}
	}
	return result
}

func TestPreviewAreaRasterMatchesReferenceAcrossFormats(t *testing.T) {
	bounds := image.Rect(-4, 3, 13, 16)
	formats := map[string]draw.Image{"nrgba": image.NewNRGBA(bounds), "rgba": image.NewRGBA(bounds), "nrgba64": image.NewNRGBA64(bounds), "rgba64": image.NewRGBA64(bounds), "gray": image.NewGray(bounds), "gray16": image.NewGray16(bounds), "paletted": image.NewPaletted(bounds, color.Palette{color.NRGBA{R: 255, A: 0}, color.NRGBA{G: 255, A: 128}, color.NRGBA{R: 50, G: 80, B: 130, A: 255}})}
	for name, source := range formats {
		t.Run(name, func(t *testing.T) {
			alphas := []uint8{0, 1, 127, 128, 254, 255}
			for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
				for x := bounds.Min.X; x < bounds.Max.X; x++ {
					i := (y-bounds.Min.Y)*bounds.Dx() + x - bounds.Min.X
					source.Set(x, y, color.NRGBA{R: uint8(i * 17), G: uint8(i * 29), B: uint8(i * 43), A: alphas[i%len(alphas)]})
				}
			}
			sources := []image.Image{source}
			if sub, ok := source.(interface {
				SubImage(image.Rectangle) image.Image
			}); ok {
				sources = append(sources, sub.SubImage(image.Rect(-1, 5, 11, 14)))
			}
			for _, input := range sources {
				for _, size := range [][2]int{{input.Bounds().Dx(), input.Bounds().Dy()}, {11, 7}, {7, 5}, {1, 1}} {
					got, err := resizePreview(context.Background(), input, size[0], size[1])
					if err != nil {
						t.Fatal(err)
					}
					want := referencePreviewArea(input, size[0], size[1])
					if !bytes.Equal(got.Pix, want.Pix) {
						t.Fatalf("premultiplied area pixels changed for bounds=%v size=%v", input.Bounds(), size)
					}
				}
			}
		})
	}
}

func TestPreviewAreaCancellationAndNeutralComposite(t *testing.T) {
	source := image.NewNRGBA(image.Rect(0, 0, 17, 13))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resizePreview(ctx, source, 11, 7); !errors.Is(err, context.Canceled) {
		t.Fatalf("area filter ignored cancellation: %v", err)
	}
	rgba := image.NewRGBA(image.Rect(-4, 3, 3, 8))
	for y := rgba.Rect.Min.Y; y < rgba.Rect.Max.Y; y++ {
		for x := rgba.Rect.Min.X; x < rgba.Rect.Max.X; x++ {
			rgba.Set(x, y, color.NRGBA{R: 140, G: 80, B: 20, A: uint8((x - rgba.Rect.Min.X + y - rgba.Rect.Min.Y) * 23)})
		}
	}
	expected := append([]byte(nil), rgba.Pix...)
	for y := 0; y < rgba.Rect.Dy(); y++ {
		for x := 0; x < rgba.Rect.Dx(); x++ {
			i := y*rgba.Stride + x*4
			alpha := int(expected[i+3])
			for c := 0; c < 3; c++ {
				expected[i+c] = uint8(min(255, int(expected[i+c])+(240*(255-alpha)+127)/255))
			}
			expected[i+3] = 255
		}
	}
	if err := compositePreview(context.Background(), rgba); err != nil || !bytes.Equal(rgba.Pix, expected) {
		t.Fatalf("neutral alpha compositing changed: %v", err)
	}
	if err := compositePreview(ctx, rgba); !errors.Is(err, context.Canceled) {
		t.Fatalf("compositing ignored cancellation: %v", err)
	}
}
