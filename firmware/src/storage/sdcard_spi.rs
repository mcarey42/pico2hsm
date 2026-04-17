//! Minimal `SpiDevice` wrapper for exclusive SD card SPI bus access.
//!
//! Unlike `embassy_embedded_hal::shared_bus::blocking::spi::SpiDevice`, this
//! wrapper does NOT use a `CriticalSectionRawMutex` (which disables interrupts
//! during blocking SPI transfers).  Since the SD card is the sole consumer of
//! its SPI bus, no mutex is needed.

use embedded_hal::digital::OutputPin;
use embedded_hal::spi::{ErrorType, Operation, SpiBus, SpiDevice};

/// A simple exclusive-access SPI device wrapper.
///
/// Manages CS assertion/deassertion around each transaction.  No mutex, no
/// critical section — the caller must ensure exclusive access.
pub struct SimpleSpiDevice<BUS, CS> {
    bus: BUS,
    cs: CS,
}

impl<BUS, CS> SimpleSpiDevice<BUS, CS> {
    /// Create a new `SimpleSpiDevice`.
    pub fn new(bus: BUS, cs: CS) -> Self {
        Self { bus, cs }
    }
}

/// Error type combining SPI bus errors and CS pin errors.
#[derive(Debug)]
pub enum SimpleDeviceError<SpiErr, CsErr> {
    /// SPI bus error.
    Spi(SpiErr),
    /// CS pin error.
    Cs(CsErr),
}

impl<SpiErr: embedded_hal::spi::Error, CsErr: core::fmt::Debug> embedded_hal::spi::Error
    for SimpleDeviceError<SpiErr, CsErr>
{
    fn kind(&self) -> embedded_hal::spi::ErrorKind {
        match self {
            SimpleDeviceError::Spi(e) => e.kind(),
            SimpleDeviceError::Cs(_) => embedded_hal::spi::ErrorKind::Other,
        }
    }
}

impl<BUS, CS> ErrorType for SimpleSpiDevice<BUS, CS>
where
    BUS: ErrorType,
    CS: OutputPin,
{
    type Error = SimpleDeviceError<BUS::Error, CS::Error>;
}

impl<BUS, CS> SpiDevice for SimpleSpiDevice<BUS, CS>
where
    BUS: SpiBus,
    CS: OutputPin,
{
    fn transaction(
        &mut self,
        operations: &mut [Operation<'_, u8>],
    ) -> Result<(), Self::Error> {
        self.cs.set_low().map_err(SimpleDeviceError::Cs)?;

        let op_res = operations.iter_mut().try_for_each(|op| match op {
            Operation::Read(buf) => self.bus.read(buf),
            Operation::Write(buf) => self.bus.write(buf),
            Operation::Transfer(read, write) => self.bus.transfer(read, write),
            Operation::TransferInPlace(buf) => self.bus.transfer_in_place(buf),
            Operation::DelayNs(_ns) => Ok(()),
        });

        // Always flush + deassert CS, even on error.
        let flush_res = self.bus.flush();
        let cs_res = self.cs.set_high();

        op_res.map_err(SimpleDeviceError::Spi)?;
        flush_res.map_err(SimpleDeviceError::Spi)?;
        cs_res.map_err(SimpleDeviceError::Cs)?;

        Ok(())
    }
}
