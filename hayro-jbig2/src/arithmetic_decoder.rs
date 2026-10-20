// Note: This is a copy of the arithmetic decoder from `hayro-jpeg2000`,
// keep the two in sync.

//! The arithmetic decoder, described in Annex C.
//!
//! The arithmetic decoder keeps track of some state and continuously receives
//! context labels as input, each time yielding a new bit from the original data
//! as output.

pub(crate) struct ArithmeticDecoder<'a> {
    /// The underlying encoded data.
    data: &'a [u8],
    /// The C-register (see Table C.1).
    c: u32,
    /// The A-register (see Table C.1).
    a: u32,
    /// The pointer to the current byte.
    base_pointer: u32,
    /// The bit shift counter.
    shift_count: u32,
}

impl<'a> ArithmeticDecoder<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        let mut decoder = ArithmeticDecoder {
            data,
            c: 0,
            a: 0,
            base_pointer: 0,
            shift_count: 0,
        };

        decoder.initialize();

        decoder
    }

    /// Read the next bit using the given context label.
    #[inline(always)]
    pub(crate) fn read_bit(&mut self, context: &mut ArithmeticDecoderContext) -> u32 {
        self.decode(context)
    }

    /// The INITDEC procedure from C.3.5.
    ///
    /// We use the version from Annex G in <https://www.itu.int/rec/T-REC-T.88-201808-I>.
    fn initialize(&mut self) {
        self.c = ((self.current_byte() as u32) ^ 0xff) << 16;
        self.read_byte();

        self.c <<= 7;
        self.shift_count -= 7;
        self.a = 0x8000;
    }

    /// The BYTEIN procedure from C.3.4.
    ///
    /// We use the version from Annex G from <https://www.itu.int/rec/T-REC-T.88-201808-I>.
    #[inline(always)]
    fn read_byte(&mut self) {
        if self.current_byte() == 0xff {
            let b1 = self.next_byte();

            if b1 > 0x8f {
                self.shift_count = 8;
            } else {
                self.base_pointer += 1;
                self.c = self
                    .c
                    .wrapping_add(0xfe00)
                    .wrapping_sub((self.current_byte() as u32) << 9);
                self.shift_count = 7;
            }
        } else {
            self.base_pointer += 1;
            self.c = self
                .c
                .wrapping_add(0xff00)
                .wrapping_sub((self.current_byte() as u32) << 8);
            self.shift_count = 8;
        }
    }

    /// The RENORMD procedure from C.3.3.
    #[inline(always)]
    fn renormalize(&mut self) {
        // Original code:
        // loop {
        //     if self.shift_count == 0 {
        //         self.read_byte();
        //     }
        //
        //     self.a <<= 1;
        //     self.c <<= 1;
        //     self.shift_count -= 1;
        //
        //     if self.a & 0x8000 != 0 {
        //         break;
        //     }
        // }

        // Optimization: Batch shifts.
        while self.a & 0x8000 == 0 {
            if self.shift_count == 0 {
                self.read_byte();
            }

            let shifts_needed = self.a.leading_zeros() - 16;
            let batch = shifts_needed.min(self.shift_count);
            self.a <<= batch;
            self.c <<= batch;
            self.shift_count -= batch;
        }
    }

    /// The `LPS_EXCHANGE` procedure from C.3.2.
    #[inline(always)]
    #[allow(unused, reason = "for reference")]
    fn exchange_lps(&mut self, context: &mut ArithmeticDecoderContext, qe_entry: &QeData) -> u32 {
        // Original code:
        // let d;
        //
        // if self.a < qe_entry.qe {
        //     self.a = qe_entry.qe;
        //     d = context.mps;
        //     context.index = qe_entry.nmps;
        // } else {
        //     self.a = qe_entry.qe;
        //     d = 1 - context.mps;
        //
        //     if qe_entry.switch {
        //         context.mps = 1 - context.mps;
        //     }
        //
        //     context.index = qe_entry.nlps;
        // }

        // Branchless version, shows better performance.

        let cond = (self.a < qe_entry.qe) as u32;
        let inv_cond = 1 - cond;

        self.a = qe_entry.qe;
        // d = if cond { mps } else { 1 - mps }
        let d = context.mps() ^ inv_cond;
        // flip mps only when !cond && switch
        context.xor_mps(inv_cond & (qe_entry.switch as u32));
        // index = if cond { nmps } else { nlps }
        let cond_u8 = cond as u8;
        let inv_cond_u8 = inv_cond as u8;
        context.set_index(cond_u8 * qe_entry.nmps + inv_cond_u8 * qe_entry.nlps);

        d
    }

    /// The `MPS_EXCHANGE` procedure from C.3.2.
    #[inline(always)]
    #[allow(unused, reason = "for reference")]
    fn exchange_mps(&mut self, context: &mut ArithmeticDecoderContext, qe_entry: &QeData) -> u32 {
        // Original code:
        //  let d;
        //
        //  if self.a < qe_entry.qe {
        //      d = 1 - context.mps;
        //
        //      if qe_entry.switch {
        //          context.mps = 1 - context.mps;
        //      }
        //
        //      context.index = qe_entry.nlps;
        //  } else {
        //      d = context.mps;
        //      context.index = qe_entry.nmps;
        //  }

        // Branchless version, shows better performance.
        let cond = (self.a < qe_entry.qe) as u32;
        let inv_cond = 1 - cond;
        // d = if cond { 1 - mps } else { mps }
        let d = context.mps() ^ cond;
        // flip mps only when cond && switch
        context.xor_mps(cond & (qe_entry.switch as u32));
        // index = if cond { nlps } else { nmps }
        let cond_u8 = cond as u8;
        let inv_cond_u8 = inv_cond as u8;
        context.set_index(cond_u8 * qe_entry.nlps + inv_cond_u8 * qe_entry.nmps);
        d
    }

    /// The DECODE procedure from C.3.2.
    ///
    /// We use the version from Annex G from <https://www.itu.int/rec/T-REC-T.88-201808-I>.
    #[inline(always)]
    pub(crate) fn decode(&mut self, context: &mut ArithmeticDecoderContext) -> u32 {
        let qe_entry = &QE_TABLE[context.index() as usize];

        self.a -= qe_entry.qe;

        // Old code:
        // let d;
        //
        // if (self.c >> 16) < self.a {
        //     if self.a & 0x8000 == 0 {
        //         d = self.exchange_mps(context, qe_entry);
        //         self.renormalize();
        //     } else {
        //         d = context.mps();
        //     }
        // } else {
        //     self.c -= self.a << 16;
        //
        //     d = self.exchange_lps(context, qe_entry);
        //     self.renormalize();
        // }
        //
        // d

        // This is a faster version that reduces branching, which has shown
        // itself to be the main limiting factor for better performance.
        // We short-circuit the case where just the most probably symbol is
        // returned, and otherwise use a code path that works for both,
        // MPS_EXCHANGE and LPS_EXCHANGE.

        if (self.c >> 16) < self.a && self.a & 0x8000 != 0 {
            return context.mps();
        }

        // Unified branchless MPS_EXCHANGE / LPS_EXCHANGE.
        //
        // Compare with exchange_mps and exchange_lps above — the only
        // difference between them is that LPS flips the role of cond:
        //   exchange_mps: d = mps ^ cond,       flip when cond,      index = cond*nlps + inv*nmps
        //   exchange_lps: d = mps ^ inv_cond,   flip when inv_cond,  index = cond*nmps + inv*nlps
        //
        // This is equivalent to XOR-ing cond with is_lps, so we can handle
        // both paths with a single branchless computation.
        //
        // As can be seen above, renormalization is always performed.
        let is_lps = ((self.c >> 16) >= self.a) as u32;

        // LPS: C -= A << 16 (no-op when MPS).
        let lps_mask = is_lps.wrapping_neg(); // 0xFFFF_FFFF if LPS, 0 if MPS
        self.c -= (self.a << 16) & lps_mask;

        // Same condition as in exchange_mps / exchange_lps.
        let cond = (self.a < qe_entry.qe) as u32;

        // LPS: a = qe (no-op when MPS, a stays as a - qe).
        self.a = (self.a & !lps_mask) | (qe_entry.qe & lps_mask);

        // exchange_mps: d = mps ^ cond       →  cond ^ 0
        // exchange_lps: d = mps ^ inv_cond   →  cond ^ 1
        // unified:      d = mps ^ (cond ^ is_lps)
        let d = context.mps() ^ cond ^ is_lps;

        // exchange_mps: flip mps when cond & switch       →  (cond ^ 0) & switch
        // exchange_lps: flip mps when inv_cond & switch   →  (cond ^ 1) & switch
        // unified:      flip mps when (cond ^ is_lps) & switch
        context.xor_mps((cond ^ is_lps) & (qe_entry.switch as u32));

        // exchange_mps: index = cond * nlps + inv_cond * nmps
        // exchange_lps: index = cond * nmps + inv_cond * nlps  (swapped)
        // unified: the result is always exactly nmps or nlps —
        //          pick nlps when (cond ^ is_lps) == 1, nmps otherwise.
        let pick_nlps = ((cond ^ is_lps) as u8).wrapping_neg(); // 0xFF or 0x00
        context.set_index(qe_entry.nmps ^ ((qe_entry.nmps ^ qe_entry.nlps) & pick_nlps));

        self.renormalize();

        d
    }

    #[inline(always)]
    fn current_byte(&self) -> u8 {
        self.data
            .get(self.base_pointer as usize)
            .copied()
            // "The number of bytes corresponding to the coding passes is
            // specified in the packet header. Often at that point there are
            // more symbols to be decoded. Therefore, the decoder shall extend
            // the input bit stream to the arithmetic coder with 0xFF bytes,
            // as necessary, until all symbols have been decoded."
            .unwrap_or(0xFF)
    }

    #[inline(always)]
    fn next_byte(&self) -> u8 {
        self.data
            .get((self.base_pointer + 1) as usize)
            .copied()
            .unwrap_or(0xFF)
    }
}

// Previously, we stored the context as 2 u32's, but doing it with a bit-packed
// u8 seems to be slightly better (though it doesn't make that huge of a
// difference).
/// Bits 0-6 = index (0-46).
/// Bit 7 = mps (0 or 1).
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct ArithmeticDecoderContext(u8);

impl ArithmeticDecoderContext {
    #[inline(always)]
    pub(crate) fn index(self) -> u32 {
        (self.0 & 0x7F) as u32
    }

    #[inline(always)]
    pub(crate) fn mps(self) -> u32 {
        (self.0 >> 7) as u32
    }

    #[inline(always)]
    fn set_index(&mut self, index: u8) {
        self.0 = (self.0 & 0x80) | index;
    }

    #[inline(always)]
    fn xor_mps(&mut self, val: u32) {
        self.0 ^= ((val & 1) << 7) as u8;
    }
}

#[derive(Debug, Clone, Copy)]
struct QeData {
    qe: u32,
    nmps: u8,
    nlps: u8,
    switch: bool,
}

macro_rules! qe {
    ($($qe:expr, $nmps:expr, $nlps:expr, $switch:expr),+ $(,)?) => {
        [
            $(
                QeData {
                    qe: $qe,
                    nmps: $nmps,
                    nlps: $nlps,
                    switch: $switch,
                }
            ),+
        ]
    };
}

/// QE values and associated data from Table C.2.
#[rustfmt::skip]
static QE_TABLE: [QeData; 47] = qe!(
    0x5601, 1, 1, true,
    0x3401, 2, 6, false,
    0x1801, 3, 9, false,
    0x0AC1, 4, 12, false,
    0x0521, 5, 29, false,
    0x0221, 38, 33, false,
    0x5601, 7, 6, true,
    0x5401, 8, 14, false,
    0x4801, 9, 14, false,
    0x3801, 10, 14, false,
    0x3001, 11, 17, false,
    0x2401, 12, 18, false,
    0x1C01, 13, 20, false,
    0x1601, 29, 21, false,
    0x5601, 15, 14, true,
    0x5401, 16, 14, false,
    0x5101, 17, 15, false,
    0x4801, 18, 16, false,
    0x3801, 19, 17, false,
    0x3401, 20, 18, false,
    0x3001, 21, 19, false,
    0x2801, 22, 19, false,
    0x2401, 23, 20, false,
    0x2201, 24, 21, false,
    0x1C01, 25, 22, false,
    0x1801, 26, 23, false,
    0x1601, 27, 24, false,
    0x1401, 28, 25, false,
    0x1201, 29, 26, false,
    0x1101, 30, 27, false,
    0x0AC1, 31, 28, false,
    0x09C1, 32, 29, false,
    0x08A1, 33, 30, false,
    0x0521, 34, 31, false,
    0x0441, 35, 32, false,
    0x02A1, 36, 33, false,
    0x0221, 37, 34, false,
    0x0141, 38, 35, false,
    0x0111, 39, 36, false,
    0x0085, 40, 37, false,
    0x0049, 41, 38, false,
    0x0025, 42, 39, false,
    0x0015, 43, 40, false,
    0x0009, 44, 41, false,
    0x0005, 45, 42, false,
    0x0001, 45, 43, false,
    0x5601, 46, 46, false,
);

#[cfg(test)]
mod tests {
    //! ITU-T T.88 Annex H.2, the test sequence for the arithmetic coder.
    //!
    //! H.2 encodes 256 decisions under one context, CX, whose I(CX) and MPS(CX) both start at 0,
    //! and Table H.1 lists, before each decision, the registers of the decoder that reads them
    //! back. This decoder follows the software conventions of Annex G, so its C register is the
    //! table's last column; A, CT, I(CX) and MPS(CX) are common to both decoders. The bytes and
    //! the register values are the annex's test vector, transcribed as data: every value in the
    //! table is what E.3's procedures compute from the two byte strings below. A failure names
    //! the event counter EC of the first row that disagrees.

    use super::{ArithmeticDecoder, ArithmeticDecoderContext};

    /// The 30 bytes H.2 states an encoder produces from `DECISIONS`.
    const ENCODED: [u8; 30] = [
        0x84, 0xC7, 0x3B, 0xFC, 0xE1, 0xA1, 0x43, 0x04, 0x02, 0x20, 0x00, 0x00, 0x41, 0x0D, 0xBB,
        0x86, 0xF4, 0x31, 0x7F, 0xFF, 0x88, 0xFF, 0x37, 0x47, 0x1A, 0xDB, 0x6A, 0xDF, 0xFF, 0xAC,
    ];

    /// The 256 decisions H.2 encodes, packed eight to a byte, most significant bit first.
    const DECISIONS: [u8; 32] = [
        0x00, 0x02, 0x00, 0x51, 0x00, 0x00, 0x00, 0xC0, 0x03, 0x52, 0x87, 0x2A, 0xAA, 0xAA, 0xAA,
        0xAA, 0x82, 0xC0, 0x20, 0x00, 0xFC, 0xD7, 0x9E, 0xF6, 0xBF, 0x7F, 0xED, 0x90, 0x4F, 0x46,
        0xA3, 0xBF,
    ];

    /// One row of Table H.1, events 1 to 256: the decision D, and the decoder's state before it.
    struct Step {
        d: u32,
        index: u32,
        mps: u32,
        a: u32,
        ct: u32,
        c: u32,
    }

    #[rustfmt::skip]
    const TABLE_H1: [Step; 256] = [
        Step { d: 0, index: 0, mps: 0, a: 0x8000, ct: 1, c: 0x3D9C0000 },
        Step { d: 0, index: 1, mps: 0, a: 0xAC02, ct: 0, c: 0x273A0000 },
        Step { d: 0, index: 2, mps: 0, a: 0xF002, ct: 7, c: 0x4E758800 },
        Step { d: 0, index: 2, mps: 0, a: 0xD801, ct: 7, c: 0x4E758800 },
        Step { d: 0, index: 2, mps: 0, a: 0xC000, ct: 7, c: 0x4E758800 },
        Step { d: 0, index: 2, mps: 0, a: 0xA7FF, ct: 7, c: 0x4E758800 },
        Step { d: 0, index: 2, mps: 0, a: 0x8FFE, ct: 7, c: 0x4E758800 },
        Step { d: 0, index: 3, mps: 0, a: 0xEFFA, ct: 6, c: 0x9CEB1000 },
        Step { d: 0, index: 3, mps: 0, a: 0xE539, ct: 6, c: 0x9CEB1000 },
        Step { d: 0, index: 3, mps: 0, a: 0xDA78, ct: 6, c: 0x9CEB1000 },
        Step { d: 0, index: 3, mps: 0, a: 0xCFB7, ct: 6, c: 0x9CEB1000 },
        Step { d: 0, index: 3, mps: 0, a: 0xC4F6, ct: 6, c: 0x9CEB1000 },
        Step { d: 0, index: 3, mps: 0, a: 0xBA35, ct: 6, c: 0x9CEB1000 },
        Step { d: 0, index: 3, mps: 0, a: 0xAF74, ct: 6, c: 0x9CEB1000 },
        Step { d: 1, index: 3, mps: 0, a: 0xA4B3, ct: 6, c: 0x9CEB1000 },
        Step { d: 0, index: 12, mps: 0, a: 0xAC10, ct: 2, c: 0x2F910000 },
        Step { d: 0, index: 12, mps: 0, a: 0x900F, ct: 2, c: 0x2F910000 },
        Step { d: 0, index: 13, mps: 0, a: 0xE81C, ct: 1, c: 0x5F220000 },
        Step { d: 0, index: 13, mps: 0, a: 0xD21B, ct: 1, c: 0x5F220000 },
        Step { d: 0, index: 13, mps: 0, a: 0xBC1A, ct: 1, c: 0x5F220000 },
        Step { d: 0, index: 13, mps: 0, a: 0xA619, ct: 1, c: 0x5F220000 },
        Step { d: 0, index: 13, mps: 0, a: 0x9018, ct: 1, c: 0x5F220000 },
        Step { d: 0, index: 29, mps: 0, a: 0xF42E, ct: 0, c: 0xBE440000 },
        Step { d: 0, index: 29, mps: 0, a: 0xE32D, ct: 0, c: 0xBE440000 },
        Step { d: 0, index: 29, mps: 0, a: 0xD22C, ct: 0, c: 0xBE440000 },
        Step { d: 1, index: 29, mps: 0, a: 0xC12B, ct: 0, c: 0xBE440000 },
        Step { d: 0, index: 27, mps: 0, a: 0x8808, ct: 5, c: 0x70D01800 },
        Step { d: 1, index: 28, mps: 0, a: 0xE80E, ct: 4, c: 0xE1A03000 },
        Step { d: 0, index: 26, mps: 0, a: 0x9008, ct: 1, c: 0x5C998000 },
        Step { d: 0, index: 27, mps: 0, a: 0xF40E, ct: 0, c: 0xB9330000 },
        Step { d: 0, index: 27, mps: 0, a: 0xE00D, ct: 0, c: 0xB9330000 },
        Step { d: 1, index: 27, mps: 0, a: 0xCC0C, ct: 0, c: 0xB9330000 },
        Step { d: 0, index: 25, mps: 0, a: 0xA008, ct: 5, c: 0x0940F000 },
        Step { d: 0, index: 25, mps: 0, a: 0x8807, ct: 5, c: 0x0940F000 },
        Step { d: 0, index: 26, mps: 0, a: 0xE00C, ct: 4, c: 0x1281E000 },
        Step { d: 0, index: 26, mps: 0, a: 0xCA0B, ct: 4, c: 0x1281E000 },
        Step { d: 0, index: 26, mps: 0, a: 0xB40A, ct: 4, c: 0x1281E000 },
        Step { d: 0, index: 26, mps: 0, a: 0x9E09, ct: 4, c: 0x1281E000 },
        Step { d: 0, index: 26, mps: 0, a: 0x8808, ct: 4, c: 0x1281E000 },
        Step { d: 0, index: 27, mps: 0, a: 0xE40E, ct: 3, c: 0x2503C000 },
        Step { d: 0, index: 27, mps: 0, a: 0xD00D, ct: 3, c: 0x2503C000 },
        Step { d: 0, index: 27, mps: 0, a: 0xBC0C, ct: 3, c: 0x2503C000 },
        Step { d: 0, index: 27, mps: 0, a: 0xA80B, ct: 3, c: 0x2503C000 },
        Step { d: 0, index: 27, mps: 0, a: 0x940A, ct: 3, c: 0x2503C000 },
        Step { d: 0, index: 27, mps: 0, a: 0x8009, ct: 3, c: 0x2503C000 },
        Step { d: 0, index: 28, mps: 0, a: 0xD810, ct: 2, c: 0x4A078000 },
        Step { d: 0, index: 28, mps: 0, a: 0xC60F, ct: 2, c: 0x4A078000 },
        Step { d: 0, index: 28, mps: 0, a: 0xB40E, ct: 2, c: 0x4A078000 },
        Step { d: 0, index: 28, mps: 0, a: 0xA20D, ct: 2, c: 0x4A078000 },
        Step { d: 0, index: 28, mps: 0, a: 0x900C, ct: 2, c: 0x4A078000 },
        Step { d: 0, index: 29, mps: 0, a: 0xFC16, ct: 1, c: 0x940F0000 },
        Step { d: 0, index: 29, mps: 0, a: 0xEB15, ct: 1, c: 0x940F0000 },
        Step { d: 0, index: 29, mps: 0, a: 0xDA14, ct: 1, c: 0x940F0000 },
        Step { d: 0, index: 29, mps: 0, a: 0xC913, ct: 1, c: 0x940F0000 },
        Step { d: 0, index: 29, mps: 0, a: 0xB812, ct: 1, c: 0x940F0000 },
        Step { d: 0, index: 29, mps: 0, a: 0xA711, ct: 1, c: 0x940F0000 },
        Step { d: 1, index: 29, mps: 0, a: 0x9610, ct: 1, c: 0x940F0000 },
        Step { d: 1, index: 27, mps: 0, a: 0x8808, ct: 6, c: 0x78017800 },
        Step { d: 0, index: 25, mps: 0, a: 0xA008, ct: 3, c: 0x1FD3C000 },
        Step { d: 0, index: 25, mps: 0, a: 0x8807, ct: 3, c: 0x1FD3C000 },
        Step { d: 0, index: 26, mps: 0, a: 0xE00C, ct: 2, c: 0x3FA78000 },
        Step { d: 0, index: 26, mps: 0, a: 0xCA0B, ct: 2, c: 0x3FA78000 },
        Step { d: 0, index: 26, mps: 0, a: 0xB40A, ct: 2, c: 0x3FA78000 },
        Step { d: 0, index: 26, mps: 0, a: 0x9E09, ct: 2, c: 0x3FA78000 },
        Step { d: 0, index: 26, mps: 0, a: 0x8808, ct: 2, c: 0x3FA78000 },
        Step { d: 0, index: 27, mps: 0, a: 0xE40E, ct: 1, c: 0x7F4F0000 },
        Step { d: 0, index: 27, mps: 0, a: 0xD00D, ct: 1, c: 0x7F4F0000 },
        Step { d: 0, index: 27, mps: 0, a: 0xBC0C, ct: 1, c: 0x7F4F0000 },
        Step { d: 0, index: 27, mps: 0, a: 0xA80B, ct: 1, c: 0x7F4F0000 },
        Step { d: 0, index: 27, mps: 0, a: 0x940A, ct: 1, c: 0x7F4F0000 },
        Step { d: 1, index: 27, mps: 0, a: 0x8009, ct: 1, c: 0x7F4F0000 },
        Step { d: 1, index: 25, mps: 0, a: 0xA008, ct: 6, c: 0x9A3AF000 },
        Step { d: 0, index: 23, mps: 0, a: 0xC008, ct: 3, c: 0x919F8000 },
        Step { d: 1, index: 23, mps: 0, a: 0x9E07, ct: 3, c: 0x919F8000 },
        Step { d: 0, index: 21, mps: 0, a: 0x8804, ct: 1, c: 0x56660000 },
        Step { d: 1, index: 22, mps: 0, a: 0xC006, ct: 0, c: 0xACCC0000 },
        Step { d: 0, index: 20, mps: 0, a: 0x9004, ct: 6, c: 0x431FEC00 },
        Step { d: 0, index: 21, mps: 0, a: 0xC006, ct: 5, c: 0x863FD800 },
        Step { d: 1, index: 21, mps: 0, a: 0x9805, ct: 5, c: 0x863FD800 },
        Step { d: 0, index: 19, mps: 0, a: 0xA004, ct: 3, c: 0x58EF6000 },
        Step { d: 1, index: 20, mps: 0, a: 0xD806, ct: 2, c: 0xB1DEC000 },
        Step { d: 0, index: 19, mps: 0, a: 0xC004, ct: 0, c: 0x27670000 },
        Step { d: 0, index: 19, mps: 0, a: 0x8C03, ct: 0, c: 0x27670000 },
        Step { d: 0, index: 20, mps: 0, a: 0xB004, ct: 7, c: 0x4ECFFA00 },
        Step { d: 0, index: 20, mps: 0, a: 0x8003, ct: 7, c: 0x4ECFFA00 },
        Step { d: 1, index: 21, mps: 0, a: 0xA004, ct: 6, c: 0x9D9FF400 },
        Step { d: 1, index: 19, mps: 0, a: 0xA004, ct: 4, c: 0x9673D000 },
        Step { d: 1, index: 18, mps: 0, a: 0xD004, ct: 2, c: 0xA9C34000 },
        Step { d: 0, index: 17, mps: 0, a: 0xE004, ct: 0, c: 0x47010000 },
        Step { d: 0, index: 17, mps: 0, a: 0x9803, ct: 0, c: 0x47010000 },
        Step { d: 1, index: 18, mps: 0, a: 0xA004, ct: 7, c: 0x8E03BE00 },
        Step { d: 0, index: 17, mps: 0, a: 0xE004, ct: 5, c: 0x9802F800 },
        Step { d: 1, index: 17, mps: 0, a: 0x9803, ct: 5, c: 0x9802F800 },
        Step { d: 0, index: 16, mps: 0, a: 0x9002, ct: 4, c: 0x9001F000 },
        Step { d: 1, index: 17, mps: 0, a: 0xA202, ct: 3, c: 0xA201E000 },
        Step { d: 0, index: 16, mps: 0, a: 0x9002, ct: 2, c: 0x9001C000 },
        Step { d: 1, index: 17, mps: 0, a: 0xA202, ct: 1, c: 0xA2018000 },
        Step { d: 0, index: 16, mps: 0, a: 0x9002, ct: 0, c: 0x90010000 },
        Step { d: 1, index: 17, mps: 0, a: 0xA202, ct: 7, c: 0xA201FE00 },
        Step { d: 0, index: 16, mps: 0, a: 0x9002, ct: 6, c: 0x9001FC00 },
        Step { d: 1, index: 17, mps: 0, a: 0xA202, ct: 5, c: 0xA201F800 },
        Step { d: 0, index: 16, mps: 0, a: 0x9002, ct: 4, c: 0x9001F000 },
        Step { d: 1, index: 17, mps: 0, a: 0xA202, ct: 3, c: 0xA201E000 },
        Step { d: 0, index: 16, mps: 0, a: 0x9002, ct: 2, c: 0x9001C000 },
        Step { d: 1, index: 17, mps: 0, a: 0xA202, ct: 1, c: 0xA2018000 },
        Step { d: 0, index: 16, mps: 0, a: 0x9002, ct: 0, c: 0x90010000 },
        Step { d: 1, index: 17, mps: 0, a: 0xA202, ct: 7, c: 0xA201FE00 },
        Step { d: 0, index: 16, mps: 0, a: 0x9002, ct: 6, c: 0x9001FC00 },
        Step { d: 1, index: 17, mps: 0, a: 0xA202, ct: 5, c: 0xA201F800 },
        Step { d: 0, index: 16, mps: 0, a: 0x9002, ct: 4, c: 0x9001F000 },
        Step { d: 1, index: 17, mps: 0, a: 0xA202, ct: 3, c: 0xA201E000 },
        Step { d: 0, index: 16, mps: 0, a: 0x9002, ct: 2, c: 0x9001C000 },
        Step { d: 1, index: 17, mps: 0, a: 0xA202, ct: 1, c: 0xA2018000 },
        Step { d: 0, index: 16, mps: 0, a: 0x9002, ct: 0, c: 0x90010000 },
        Step { d: 1, index: 17, mps: 0, a: 0xA202, ct: 7, c: 0xA2017C00 },
        Step { d: 0, index: 16, mps: 0, a: 0x9002, ct: 6, c: 0x9000F800 },
        Step { d: 1, index: 17, mps: 0, a: 0xA202, ct: 5, c: 0xA1FFF000 },
        Step { d: 0, index: 16, mps: 0, a: 0x9002, ct: 4, c: 0x8FFDE000 },
        Step { d: 1, index: 17, mps: 0, a: 0xA202, ct: 3, c: 0xA1F9C000 },
        Step { d: 0, index: 16, mps: 0, a: 0x9002, ct: 2, c: 0x8FF18000 },
        Step { d: 1, index: 17, mps: 0, a: 0xA202, ct: 1, c: 0xA1E10000 },
        Step { d: 0, index: 16, mps: 0, a: 0x9002, ct: 0, c: 0x8FC00000 },
        Step { d: 1, index: 17, mps: 0, a: 0xA202, ct: 7, c: 0xA17FE400 },
        Step { d: 0, index: 16, mps: 0, a: 0x9002, ct: 6, c: 0x8EFDC800 },
        Step { d: 1, index: 17, mps: 0, a: 0xA202, ct: 5, c: 0x9FF99000 },
        Step { d: 0, index: 16, mps: 0, a: 0x9002, ct: 4, c: 0x8BF12000 },
        Step { d: 1, index: 17, mps: 0, a: 0xA202, ct: 3, c: 0x99E04000 },
        Step { d: 0, index: 16, mps: 0, a: 0x9002, ct: 2, c: 0x7FBE8000 },
        Step { d: 1, index: 17, mps: 0, a: 0xA202, ct: 1, c: 0x817B0000 },
        Step { d: 0, index: 16, mps: 0, a: 0x9002, ct: 0, c: 0x4EF40000 },
        Step { d: 0, index: 17, mps: 0, a: 0xA202, ct: 7, c: 0x1FE68800 },
        Step { d: 0, index: 18, mps: 0, a: 0xB402, ct: 6, c: 0x3FCD1000 },
        Step { d: 0, index: 19, mps: 0, a: 0xF802, ct: 5, c: 0x7F9A2000 },
        Step { d: 0, index: 19, mps: 0, a: 0xC401, ct: 5, c: 0x7F9A2000 },
        Step { d: 1, index: 19, mps: 0, a: 0x9000, ct: 5, c: 0x7F9A2000 },
        Step { d: 0, index: 18, mps: 0, a: 0xD004, ct: 3, c: 0x8E6C8000 },
        Step { d: 1, index: 18, mps: 0, a: 0x9803, ct: 3, c: 0x8E6C8000 },
        Step { d: 1, index: 17, mps: 0, a: 0xE004, ct: 1, c: 0xB9AA0000 },
        Step { d: 0, index: 16, mps: 0, a: 0x9002, ct: 0, c: 0x434E0000 },
        Step { d: 0, index: 17, mps: 0, a: 0xA202, ct: 7, c: 0x089AF200 },
        Step { d: 0, index: 18, mps: 0, a: 0xB402, ct: 6, c: 0x1135E400 },
        Step { d: 0, index: 19, mps: 0, a: 0xF802, ct: 5, c: 0x226BC800 },
        Step { d: 0, index: 19, mps: 0, a: 0xC401, ct: 5, c: 0x226BC800 },
        Step { d: 0, index: 19, mps: 0, a: 0x9000, ct: 5, c: 0x226BC800 },
        Step { d: 0, index: 20, mps: 0, a: 0xB7FE, ct: 4, c: 0x44D79000 },
        Step { d: 0, index: 20, mps: 0, a: 0x87FD, ct: 4, c: 0x44D79000 },
        Step { d: 1, index: 21, mps: 0, a: 0xAFF8, ct: 3, c: 0x89AF2000 },
        Step { d: 0, index: 19, mps: 0, a: 0xA004, ct: 1, c: 0x06E08000 },
        Step { d: 0, index: 20, mps: 0, a: 0xD806, ct: 0, c: 0x0DC10000 },
        Step { d: 0, index: 20, mps: 0, a: 0xA805, ct: 0, c: 0x0DC10000 },
        Step { d: 0, index: 21, mps: 0, a: 0xF008, ct: 7, c: 0x1B821600 },
        Step { d: 0, index: 21, mps: 0, a: 0xC807, ct: 7, c: 0x1B821600 },
        Step { d: 0, index: 21, mps: 0, a: 0xA006, ct: 7, c: 0x1B821600 },
        Step { d: 0, index: 22, mps: 0, a: 0xF00A, ct: 6, c: 0x37042C00 },
        Step { d: 0, index: 22, mps: 0, a: 0xCC09, ct: 6, c: 0x37042C00 },
        Step { d: 0, index: 22, mps: 0, a: 0xA808, ct: 6, c: 0x37042C00 },
        Step { d: 0, index: 22, mps: 0, a: 0x8407, ct: 6, c: 0x37042C00 },
        Step { d: 0, index: 23, mps: 0, a: 0xC00C, ct: 5, c: 0x6E085800 },
        Step { d: 0, index: 23, mps: 0, a: 0x9E0B, ct: 5, c: 0x6E085800 },
        Step { d: 0, index: 24, mps: 0, a: 0xF814, ct: 4, c: 0xDC10B000 },
        Step { d: 1, index: 24, mps: 0, a: 0xDC13, ct: 4, c: 0xDC10B000 },
        Step { d: 1, index: 22, mps: 0, a: 0xE008, ct: 1, c: 0xDFF58000 },
        Step { d: 1, index: 20, mps: 0, a: 0x9004, ct: 7, c: 0x8FBB9C00 },
        Step { d: 1, index: 19, mps: 0, a: 0xC004, ct: 5, c: 0xBEE27000 },
        Step { d: 1, index: 18, mps: 0, a: 0xD004, ct: 3, c: 0xCB7DC000 },
        Step { d: 1, index: 17, mps: 0, a: 0xE004, ct: 1, c: 0xCDEB0000 },
        Step { d: 0, index: 16, mps: 0, a: 0x9002, ct: 0, c: 0x6BD00000 },
        Step { d: 0, index: 17, mps: 0, a: 0xA202, ct: 7, c: 0x599F0000 },
        Step { d: 1, index: 18, mps: 0, a: 0xB402, ct: 6, c: 0xB33E0000 },
        Step { d: 1, index: 17, mps: 0, a: 0xE004, ct: 4, c: 0xDCF40000 },
        Step { d: 0, index: 16, mps: 0, a: 0x9002, ct: 3, c: 0x89E20000 },
        Step { d: 1, index: 17, mps: 0, a: 0xA202, ct: 2, c: 0x95C20000 },
        Step { d: 0, index: 16, mps: 0, a: 0x9002, ct: 1, c: 0x77820000 },
        Step { d: 1, index: 17, mps: 0, a: 0xA202, ct: 0, c: 0x71020000 },
        Step { d: 1, index: 16, mps: 0, a: 0x9002, ct: 7, c: 0x2E020000 },
        Step { d: 1, index: 15, mps: 0, a: 0xFC04, ct: 5, c: 0xB8080000 },
        Step { d: 1, index: 14, mps: 0, a: 0xA802, ct: 4, c: 0x200A0000 },
        Step { d: 0, index: 14, mps: 1, a: 0xA402, ct: 3, c: 0x40140000 },
        Step { d: 0, index: 14, mps: 0, a: 0x9C02, ct: 2, c: 0x80280000 },
        Step { d: 1, index: 15, mps: 0, a: 0xAC02, ct: 1, c: 0x744E0000 },
        Step { d: 1, index: 14, mps: 0, a: 0xA802, ct: 0, c: 0x389A0000 },
        Step { d: 1, index: 14, mps: 1, a: 0xA402, ct: 6, c: 0x7133DC00 },
        Step { d: 1, index: 15, mps: 1, a: 0xAC02, ct: 5, c: 0x4665B800 },
        Step { d: 0, index: 16, mps: 1, a: 0xB002, ct: 4, c: 0x8CCB7000 },
        Step { d: 1, index: 15, mps: 1, a: 0xA202, ct: 3, c: 0x5B94E000 },
        Step { d: 1, index: 16, mps: 1, a: 0xA802, ct: 2, c: 0x1B27C000 },
        Step { d: 1, index: 17, mps: 1, a: 0xAE02, ct: 1, c: 0x364F8000 },
        Step { d: 1, index: 18, mps: 1, a: 0xCC02, ct: 0, c: 0x6C9F0000 },
        Step { d: 0, index: 18, mps: 1, a: 0x9401, ct: 0, c: 0x6C9F0000 },
        Step { d: 1, index: 17, mps: 1, a: 0xE004, ct: 6, c: 0x427C0000 },
        Step { d: 1, index: 17, mps: 1, a: 0x9803, ct: 6, c: 0x427C0000 },
        Step { d: 0, index: 18, mps: 1, a: 0xA004, ct: 5, c: 0x84F80000 },
        Step { d: 1, index: 17, mps: 1, a: 0xE004, ct: 3, c: 0x73D40000 },
        Step { d: 0, index: 17, mps: 1, a: 0x9803, ct: 3, c: 0x73D40000 },
        Step { d: 1, index: 16, mps: 1, a: 0x9002, ct: 2, c: 0x47A40000 },
        Step { d: 1, index: 17, mps: 1, a: 0xA202, ct: 1, c: 0x11460000 },
        Step { d: 1, index: 18, mps: 1, a: 0xB402, ct: 0, c: 0x228C0000 },
        Step { d: 1, index: 19, mps: 1, a: 0xF802, ct: 6, c: 0x45192000 },
        Step { d: 1, index: 19, mps: 1, a: 0xC401, ct: 6, c: 0x45192000 },
        Step { d: 1, index: 19, mps: 1, a: 0x9000, ct: 6, c: 0x45192000 },
        Step { d: 0, index: 20, mps: 1, a: 0xB7FE, ct: 5, c: 0x8A324000 },
        Step { d: 1, index: 19, mps: 1, a: 0xC004, ct: 3, c: 0x08D50000 },
        Step { d: 1, index: 19, mps: 1, a: 0x8C03, ct: 3, c: 0x08D50000 },
        Step { d: 1, index: 20, mps: 1, a: 0xB004, ct: 2, c: 0x11AA0000 },
        Step { d: 1, index: 20, mps: 1, a: 0x8003, ct: 2, c: 0x11AA0000 },
        Step { d: 1, index: 21, mps: 1, a: 0xA004, ct: 1, c: 0x23540000 },
        Step { d: 1, index: 22, mps: 1, a: 0xF006, ct: 0, c: 0x46A80000 },
        Step { d: 1, index: 22, mps: 1, a: 0xCC05, ct: 0, c: 0x46A80000 },
        Step { d: 1, index: 22, mps: 1, a: 0xA804, ct: 0, c: 0x46A80000 },
        Step { d: 1, index: 22, mps: 1, a: 0x8403, ct: 0, c: 0x46A80000 },
        Step { d: 1, index: 23, mps: 1, a: 0xC004, ct: 7, c: 0x8D517000 },
        Step { d: 0, index: 23, mps: 1, a: 0x9E03, ct: 7, c: 0x8D517000 },
        Step { d: 1, index: 21, mps: 1, a: 0x8804, ct: 5, c: 0x453DC000 },
        Step { d: 1, index: 22, mps: 1, a: 0xC006, ct: 4, c: 0x8A7B8000 },
        Step { d: 0, index: 22, mps: 1, a: 0x9C05, ct: 4, c: 0x8A7B8000 },
        Step { d: 1, index: 20, mps: 1, a: 0x9004, ct: 2, c: 0x49DE0000 },
        Step { d: 1, index: 21, mps: 1, a: 0xC006, ct: 1, c: 0x93BC0000 },
        Step { d: 0, index: 21, mps: 1, a: 0x9805, ct: 1, c: 0x93BC0000 },
        Step { d: 0, index: 19, mps: 1, a: 0xA004, ct: 7, c: 0x8EE1CA00 },
        Step { d: 1, index: 18, mps: 1, a: 0xD004, ct: 5, c: 0x8B7B2800 },
        Step { d: 0, index: 18, mps: 1, a: 0x9803, ct: 5, c: 0x8B7B2800 },
        Step { d: 0, index: 17, mps: 1, a: 0xE004, ct: 3, c: 0xADE4A000 },
        Step { d: 0, index: 16, mps: 1, a: 0x9002, ct: 2, c: 0x2BC34000 },
        Step { d: 0, index: 15, mps: 1, a: 0xFC04, ct: 0, c: 0xAF0D0000 },
        Step { d: 0, index: 14, mps: 1, a: 0xA802, ct: 7, c: 0x0E144800 },
        Step { d: 1, index: 14, mps: 0, a: 0xA402, ct: 6, c: 0x1C289000 },
        Step { d: 0, index: 14, mps: 1, a: 0x9C02, ct: 5, c: 0x38512000 },
        Step { d: 0, index: 14, mps: 0, a: 0x8C02, ct: 4, c: 0x70A24000 },
        Step { d: 1, index: 15, mps: 0, a: 0xAC02, ct: 3, c: 0x75428000 },
        Step { d: 1, index: 14, mps: 0, a: 0xA802, ct: 2, c: 0x3A830000 },
        Step { d: 1, index: 14, mps: 1, a: 0xA402, ct: 1, c: 0x75060000 },
        Step { d: 1, index: 15, mps: 1, a: 0xAC02, ct: 0, c: 0x4E0A0000 },
        Step { d: 0, index: 16, mps: 1, a: 0xB002, ct: 7, c: 0x9C152A00 },
        Step { d: 1, index: 15, mps: 1, a: 0xA202, ct: 6, c: 0x7A285400 },
        Step { d: 0, index: 16, mps: 1, a: 0xA802, ct: 5, c: 0x584EA800 },
        Step { d: 0, index: 15, mps: 1, a: 0xA202, ct: 4, c: 0x029B5000 },
        Step { d: 0, index: 14, mps: 1, a: 0x9C02, ct: 3, c: 0x0536A000 },
        Step { d: 1, index: 14, mps: 0, a: 0x8C02, ct: 2, c: 0x0A6D4000 },
        Step { d: 1, index: 14, mps: 1, a: 0xD804, ct: 0, c: 0x29B50000 },
        Step { d: 0, index: 14, mps: 1, a: 0x8203, ct: 0, c: 0x29B50000 },
        Step { d: 1, index: 14, mps: 0, a: 0xB008, ct: 6, c: 0xA6D48000 },
        Step { d: 0, index: 14, mps: 1, a: 0xAC02, ct: 5, c: 0x999B0000 },
        Step { d: 1, index: 14, mps: 0, a: 0xAC02, ct: 4, c: 0x87340000 },
        Step { d: 0, index: 14, mps: 1, a: 0xAC02, ct: 3, c: 0x62660000 },
        Step { d: 0, index: 14, mps: 0, a: 0xAC02, ct: 2, c: 0x18CA0000 },
        Step { d: 0, index: 15, mps: 0, a: 0xAC02, ct: 1, c: 0x31940000 },
        Step { d: 1, index: 16, mps: 0, a: 0xB002, ct: 0, c: 0x63280000 },
        Step { d: 1, index: 15, mps: 0, a: 0xA202, ct: 7, c: 0x084E0000 },
        Step { d: 1, index: 14, mps: 0, a: 0x9C02, ct: 6, c: 0x109C0000 },
        Step { d: 0, index: 14, mps: 1, a: 0x8C02, ct: 5, c: 0x21380000 },
        Step { d: 1, index: 14, mps: 0, a: 0xD804, ct: 3, c: 0x84E00000 },
        Step { d: 1, index: 14, mps: 1, a: 0xAC02, ct: 2, c: 0x05BA0000 },
        Step { d: 1, index: 15, mps: 1, a: 0xAC02, ct: 1, c: 0x0B740000 },
        Step { d: 1, index: 16, mps: 1, a: 0xB002, ct: 0, c: 0x16E80000 },
        Step { d: 1, index: 17, mps: 1, a: 0xBE02, ct: 7, c: 0x2DD00000 },
        Step { d: 1, index: 18, mps: 1, a: 0xEC02, ct: 6, c: 0x5BA00000 },
    ];

    #[test]
    fn table_h1_decision_by_decision() {
        let mut decoder = ArithmeticDecoder::new(&ENCODED);
        let mut cx = ArithmeticDecoderContext::default();

        for (event, step) in TABLE_H1.iter().enumerate() {
            let event = event + 1;
            let expected_bit = u32::from(DECISIONS[(event - 1) / 8] >> (7 - (event - 1) % 8)) & 1;
            assert_eq!(
                step.d, expected_bit,
                "EC {event}: Table H.1 and the 32 bytes disagree"
            );

            assert_eq!(cx.index(), step.index, "EC {event}: I(CX)");
            assert_eq!(cx.mps(), step.mps, "EC {event}: MPS(CX)");
            assert_eq!(decoder.a, step.a, "EC {event}: A");
            assert_eq!(decoder.c, step.c, "EC {event}: C (software conventions)");
            assert_eq!(decoder.shift_count, step.ct, "EC {event}: CT");

            assert_eq!(decoder.decode(&mut cx), step.d, "EC {event}: D");
        }
    }
}
