//! Band render target: a few full-width rows of packed RGB444.
//!
//! The screen is never held in RAM.  It is drawn 16 rows at a time into a
//! small band buffer and each band is sent to the panel as one window and
//! one DMA transfer (design spec §3).  Full-width bands mean every row
//! starts on a pixel pair, so the 3-bytes-per-2-pixels packing never needs
//! a read-modify-write across a band edge.
//!
//! Packing (ST7789 "interface II" RGB444, two pixels in three bytes):
//! ```text
//! byte 0: R1 G1    byte 1: B1 R2    byte 2: G2 B2
//! ```

use embedded_graphics::{
    draw_target::DrawTarget,
    geometry::{Dimensions, Point, Size},
    primitives::Rectangle,
    Pixel,
};

use super::color::C444;

/// Rows per band.
pub const BAND_ROWS: u16 = 16;

/// Bytes for `rows` full rows of a `width`-pixel panel (`width` even).
pub const fn band_bytes(width: u16, rows: u16) -> usize {
    width as usize * rows as usize * 3 / 2
}

/// A `DrawTarget` over rows `y0 .. y0 + h` of a `w`-pixel-wide screen.
/// Pixels outside those rows (or outside the screen width) are dropped.
pub struct Rgb444Band<'a> {
    buf: &'a mut [u8],
    w: u16,
    y0: u16,
    h: u16,
}

impl<'a> Rgb444Band<'a> {
    /// A band over `buf`, which must hold at least `band_bytes(w, h)`.
    pub fn new(buf: &'a mut [u8], w: u16, y0: u16, h: u16) -> Self {
        debug_assert!(w % 2 == 0);
        debug_assert!(buf.len() >= band_bytes(w, h));
        Rgb444Band { buf, w, y0, h }
    }

    /// The packed bytes of the band.
    pub fn bytes(&self) -> &[u8] {
        &self.buf[..band_bytes(self.w, self.h)]
    }

    /// The rectangle the band covers, in screen coordinates.
    pub fn rect(&self) -> Rectangle {
        Rectangle::new(
            Point::new(0, i32::from(self.y0)),
            Size::new(u32::from(self.w), u32::from(self.h)),
        )
    }

    #[inline(always)]
    fn set(&mut self, x: usize, row: usize, c: C444) {
        let idx = row * self.w as usize + x;
        let base = idx / 2 * 3;
        let (r, g, b) = (c.r(), c.g(), c.b());
        if idx % 2 == 0 {
            self.buf[base] = (r << 4) | g;
            self.buf[base + 1] = (self.buf[base + 1] & 0x0F) | (b << 4);
        } else {
            self.buf[base + 1] = (self.buf[base + 1] & 0xF0) | r;
            self.buf[base + 2] = (g << 4) | b;
        }
    }

    /// Fill pixels `x0 .. x1` of band row `row` (both in range).
    fn span(&mut self, row: usize, mut x0: usize, mut x1: usize, c: C444) {
        if x0 >= x1 {
            return;
        }
        if x0 % 2 == 1 {
            self.set(x0, row, c);
            x0 += 1;
        }
        if x1 % 2 == 1 && x1 > x0 {
            self.set(x1 - 1, row, c);
            x1 -= 1;
        }
        if x0 >= x1 {
            return;
        }
        let (r, g, b) = (c.r(), c.g(), c.b());
        let pair = [(r << 4) | g, (b << 4) | r, (g << 4) | b];
        let pat = [
            pair[0], pair[1], pair[2], pair[0], pair[1], pair[2], pair[0], pair[1], pair[2],
            pair[0], pair[1], pair[2],
        ];
        let row_base = row * self.w as usize * 3 / 2;
        let bytes = &mut self.buf[row_base + x0 * 3 / 2..row_base + x1 * 3 / 2];
        let mut chunks = bytes.chunks_exact_mut(12);
        for ch in &mut chunks {
            ch.copy_from_slice(&pat);
        }
        let rest = chunks.into_remainder();
        let n = rest.len();
        rest.copy_from_slice(&pat[..n]);
    }
}

impl Dimensions for Rgb444Band<'_> {
    fn bounding_box(&self) -> Rectangle {
        self.rect()
    }
}

impl DrawTarget for Rgb444Band<'_> {
    type Color = C444;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        let (w, y0, h) = (i32::from(self.w), i32::from(self.y0), i32::from(self.h));
        for Pixel(p, c) in pixels {
            if p.x >= 0 && p.x < w && p.y >= y0 && p.y < y0 + h {
                self.set(p.x as usize, (p.y - y0) as usize, c);
            }
        }
        Ok(())
    }

    fn fill_solid(&mut self, area: &Rectangle, color: Self::Color) -> Result<(), Self::Error> {
        let a = area.intersection(&self.rect());
        if a.size.width == 0 || a.size.height == 0 {
            return Ok(());
        }
        let x0 = a.top_left.x as usize;
        let x1 = x0 + a.size.width as usize;
        let r0 = (a.top_left.y - i32::from(self.y0)) as usize;
        for row in r0..r0 + a.size.height as usize {
            self.span(row, x0, x1, color);
        }
        Ok(())
    }
}

/// Pixel-doubling wrapper: everything drawn at `(x, y)` lands as a 2×2
/// block at `origin + 2·(x, y)` on the inner target.  No buffer.
pub struct Scale2<'a, D> {
    inner: &'a mut D,
    origin: Point,
}

impl<'a, D> Scale2<'a, D> {
    /// Draw into `inner`, scaled ×2, with `(0, 0)` at `origin`.
    pub fn new(inner: &'a mut D, origin: Point) -> Self {
        Scale2 { inner, origin }
    }
}

impl<D: DrawTarget> Dimensions for Scale2<'_, D> {
    fn bounding_box(&self) -> Rectangle {
        let b = self.inner.bounding_box();
        Rectangle::new(
            Point::new(
                (b.top_left.x - self.origin.x) / 2,
                (b.top_left.y - self.origin.y) / 2,
            ),
            Size::new(b.size.width / 2 + 1, b.size.height / 2 + 1),
        )
    }
}

impl<D: DrawTarget> DrawTarget for Scale2<'_, D> {
    type Color = D::Color;
    type Error = D::Error;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        for Pixel(p, c) in pixels {
            let at = Point::new(self.origin.x + p.x * 2, self.origin.y + p.y * 2);
            self.inner
                .fill_solid(&Rectangle::new(at, Size::new(2, 2)), c)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(buf: &[u8], w: usize, x: usize, row: usize) -> u16 {
        let idx = row * w + x;
        let base = idx / 2 * 3;
        if idx % 2 == 0 {
            (u16::from(buf[base]) << 4) | u16::from(buf[base + 1] >> 4)
        } else {
            (u16::from(buf[base + 1] & 0xF) << 8) | u16::from(buf[base + 2])
        }
    }

    #[test]
    fn span_fill_matches_pixel_writes() {
        // Every start/end parity, every remainder length of the 12-byte copy.
        let w = 40u16;
        for x0 in 0..12 {
            for x1 in x0..w as usize {
                let mut a = [0u8; band_bytes(40, 2)];
                let mut b = [0u8; band_bytes(40, 2)];
                let c = C444::hex(0x5A3);
                let mut ta = Rgb444Band::new(&mut a, w, 10, 2);
                ta.fill_solid(
                    &Rectangle::new(Point::new(x0 as i32, 11), Size::new((x1 - x0) as u32, 1)),
                    c,
                )
                .unwrap();
                let mut tb = Rgb444Band::new(&mut b, w, 10, 2);
                tb.draw_iter((x0..x1).map(|x| Pixel(Point::new(x as i32, 11), c)))
                    .unwrap();
                assert_eq!(a, b, "x0={x0} x1={x1}");
            }
        }
    }

    #[test]
    fn clips_to_band_rows() {
        let mut buf = [0u8; band_bytes(8, 2)];
        let mut t = Rgb444Band::new(&mut buf, 8, 4, 2);
        t.fill_solid(
            &Rectangle::new(Point::new(-3, 0), Size::new(20, 20)),
            C444::hex(0xFFF),
        )
        .unwrap();
        t.draw_iter([Pixel(Point::new(0, 3), C444::hex(0x123))])
            .unwrap();
        for row in 0..2 {
            for x in 0..8 {
                assert_eq!(get(&buf, 8, x, row), 0xFFF);
            }
        }
    }

    #[test]
    fn scale2_doubles() {
        let mut buf = [0u8; band_bytes(8, 4)];
        let mut t = Rgb444Band::new(&mut buf, 8, 0, 4);
        let mut s = Scale2::new(&mut t, Point::new(2, 0));
        s.draw_iter([Pixel(Point::new(1, 1), C444::hex(0xF00))])
            .unwrap();
        for (x, row) in [(4, 2), (5, 2), (4, 3), (5, 3)] {
            assert_eq!(get(&buf, 8, x, row), 0xF00);
        }
        assert_eq!(get(&buf, 8, 3, 2), 0);
    }
}
