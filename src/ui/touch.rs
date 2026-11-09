//! Presentation of native touch-wait notifications; credentials stay on the app thread.
use std::{
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    time::Duration,
};

use ratatui::{
    Frame, Terminal,
    backend::Backend,
    buffer::Buffer,
    layout::{Alignment, Rect},
    style::Style,
    widgets::{Clear, Paragraph},
};

const MESSAGE: &str = "Touch your YubiKey to continue...";

fn draw(frame: &mut Frame, background: &Buffer, waiting: bool, style: Style) {
    let area = frame.area().intersection(background.area);
    for y in area.y..area.bottom() {
        for x in area.x..area.right() {
            frame.buffer_mut()[(x, y)] = background[(x, y)].clone();
        }
    }
    if waiting {
        let area = frame.area();
        let line = Rect::new(
            area.x,
            area.bottom().saturating_sub(1),
            area.width,
            area.height.min(1),
        );
        frame.render_widget(Clear, line);
        frame.render_widget(
            Paragraph::new(MESSAGE)
                .alignment(Alignment::Center)
                .style(style),
            line,
        );
    }
}

fn present<B: Backend>(
    terminal: &mut Terminal<B>,
    background: &Buffer,
    style: Style,
    receiver: Receiver<bool>,
) -> Result<(), B::Error> {
    let mut visible = false;
    loop {
        let waiting = match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(waiting) => receiver.try_iter().last().unwrap_or(waiting),
            Err(RecvTimeoutError::Timeout) => visible,
            Err(RecvTimeoutError::Disconnected) => {
                if visible {
                    terminal.draw(|frame| draw(frame, background, false, style))?;
                }
                return Ok(());
            }
        };
        if waiting || visible {
            terminal.draw(|frame| draw(frame, background, waiting, style))?;
        }
        visible = waiting;
    }
}

/// Only rendering moves to a scoped thread. Authentication, cancellation and
/// operation-local physical device ownership remain on their original thread.
pub fn with_prompt<B, T>(
    terminal: &mut Terminal<B>,
    background: Buffer,
    style: Style,
    action: impl FnOnce() -> T,
) -> Result<T, B::Error>
where
    B: Backend + Send,
    B::Error: Send,
{
    std::thread::scope(|scope| {
        let (sender, receiver) = mpsc::channel();
        let renderer = scope.spawn(move || present(terminal, &background, style, receiver));
        let observer = challenge_response::touch::Observer::install(sender);
        let result = action();
        drop(observer);
        renderer.join().expect("touch prompt renderer panicked")?;
        Ok(result)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use challenge_response::touch::Observer;
    use ratatui::{
        backend::{ClearType, TestBackend, WindowSize},
        buffer::Cell,
        layout::{Position, Size},
        widgets::Paragraph,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Sender},
    };

    struct ObservedBackend {
        inner: TestBackend,
        frames: Sender<Buffer>,
    }
    impl Backend for ObservedBackend {
        type Error = <TestBackend as Backend>::Error;
        fn draw<'a, I>(&mut self, content: I) -> Result<(), Self::Error>
        where
            I: Iterator<Item = (u16, u16, &'a Cell)>,
        {
            self.inner.draw(content)
        }
        fn hide_cursor(&mut self) -> Result<(), Self::Error> {
            self.inner.hide_cursor()
        }
        fn show_cursor(&mut self) -> Result<(), Self::Error> {
            self.inner.show_cursor()
        }
        fn get_cursor_position(&mut self) -> Result<Position, Self::Error> {
            self.inner.get_cursor_position()
        }
        fn set_cursor_position<P: Into<Position>>(&mut self, p: P) -> Result<(), Self::Error> {
            self.inner.set_cursor_position(p)
        }
        fn clear(&mut self) -> Result<(), Self::Error> {
            self.inner.clear()
        }
        fn clear_region(&mut self, region: ClearType) -> Result<(), Self::Error> {
            self.inner.clear_region(region)
        }
        fn size(&self) -> Result<Size, Self::Error> {
            self.inner.size()
        }
        fn window_size(&mut self) -> Result<WindowSize, Self::Error> {
            self.inner.window_size()
        }
        fn flush(&mut self) -> Result<(), Self::Error> {
            self.inner.flush()?;
            let _ = self.frames.send(self.inner.buffer().clone());
            Ok(())
        }
    }

    fn visible(buffer: &Buffer) -> bool {
        buffer
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>()
            .contains(MESSAGE)
    }

    fn blocked_poll_is_presented_and_cleared(outcome: u8) {
        for status in [0x21, 0xa1] {
            let (sender, frames) = mpsc::channel();
            let mut terminal = Terminal::new(ObservedBackend {
                inner: TestBackend::new(60, 8),
                frames: sender,
            })
            .unwrap();
            let background = terminal
                .draw(|frame| {
                    frame.render_widget(Paragraph::new("original login screen"), frame.area());
                })
                .unwrap()
                .buffer
                .clone();
            let _ = frames.try_iter().count();
            let flag = Arc::new(AtomicBool::new(false));
            let _cancel = challenge_response::operation::Cancellation::install(Arc::clone(&flag));
            let result = with_prompt(&mut terminal, background.clone(), Style::default(), || {
                challenge_response::test_support::touch_wait_for(status, || {
                    // Do not release the synchronous polling operation until a
                    // flushed frame, not just a queued notification, is visible.
                    let frame = frames
                        .recv_timeout(Duration::from_secs(2))
                        .expect("no frame while operation is blocked");
                    assert!(
                        visible(&frame),
                        "touch prompt missing while operation is blocked"
                    );
                    match outcome {
                        0 => Ok(()),
                        1 => Err(
                            challenge_response::error::ChallengeResponseError::CanNotReadFromDevice,
                        ),
                        _ => {
                            flag.store(true, Ordering::SeqCst);
                            challenge_response::operation::check()
                        }
                    }
                })
            })
            .unwrap();
            match outcome {
                0 => assert!(result.is_ok()),
                1 => assert!(matches!(
                    result,
                    Err(challenge_response::error::ChallengeResponseError::CanNotReadFromDevice)
                )),
                _ => assert!(matches!(
                    result,
                    Err(challenge_response::error::ChallengeResponseError::Cancelled)
                )),
            }
            assert_eq!(terminal.backend().inner.buffer(), &background);
        }
    }

    #[test]
    fn blocked_touch_poll_renders_before_success_and_clears() {
        blocked_poll_is_presented_and_cleared(0);
    }

    #[test]
    fn blocked_touch_poll_renders_before_error_and_clears() {
        blocked_poll_is_presented_and_cleared(1);
    }

    #[test]
    fn blocked_touch_poll_renders_before_cancellation_and_clears() {
        blocked_poll_is_presented_and_cleared(2);
    }

    #[test]
    #[ignore = "requires a real PTY; synthetic OTP reports only, no hardware"]
    fn crossterm_flushes_touch_prompt_while_poll_is_blocked_in_a_pty() {
        use std::io::{self, IsTerminal, Write};
        struct Output {
            stdout: io::Stdout,
            bytes: Vec<u8>,
            flushed: Sender<()>,
        }
        impl Write for Output {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let n = self.stdout.write(bytes)?;
                self.bytes.extend_from_slice(&bytes[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                self.stdout.flush()?;
                // Crossterm cursor moves can separate words in a buffer diff.
                // The exact rendered sentence is checked by the buffer tests.
                if self.bytes.windows(5).any(|s| s == b"Touch")
                    && self.bytes.windows(7).any(|s| s == b"YubiKey")
                {
                    let _ = self.flushed.send(());
                }
                self.bytes.clear();
                Ok(())
            }
        }
        assert!(io::stdout().is_terminal(), "run this test with --pty");
        let (sender, flushed) = mpsc::channel();
        let mut terminal = Terminal::new(ratatui::backend::CrosstermBackend::new(Output {
            stdout: io::stdout(),
            bytes: Vec::new(),
            flushed: sender,
        }))
        .unwrap();
        let background = terminal
            .draw(|frame| {
                frame.render_widget(Paragraph::new("synthetic login screen"), frame.area());
            })
            .unwrap()
            .buffer
            .clone();
        let result = with_prompt(&mut terminal, background, Style::default(), || {
            challenge_response::test_support::touch_wait_for(0xa1, || {
                flushed
                    .recv_timeout(Duration::from_secs(2))
                    .expect("Crossterm did not flush the prompt before the wait ended");
                Ok(())
            })
        })
        .unwrap();
        assert!(result.is_ok());
    }

    #[test]
    fn prompt_is_rendered_and_cleared_without_replacing_the_original_screen() {
        use ratatui::{Terminal, backend::TestBackend, style::Style, widgets::Paragraph};
        let mut terminal = Terminal::new(TestBackend::new(60, 8)).unwrap();
        let background = terminal
            .draw(|frame| {
                frame.render_widget(Paragraph::new("original login screen"), frame.area())
            })
            .unwrap()
            .buffer
            .clone();
        terminal
            .draw(|frame| super::draw(frame, &background, true, Style::default()))
            .unwrap();
        let contents: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(contents.contains(super::MESSAGE));
        terminal
            .draw(|frame| super::draw(frame, &background, false, Style::default()))
            .unwrap();
        assert_eq!(terminal.backend().buffer(), &background);
        super::with_prompt(&mut terminal, background, Style::default(), || {
            challenge_response::test_support::touch_wait_reports(&[0x21, 0x40]);
            "unchanged authentication result"
        })
        .map(|result| assert_eq!(result, "unchanged authentication result"))
        .unwrap();
    }

    #[test]
    fn touch_prompt_tracks_only_the_device_touch_wait_flag() {
        let (sender, receiver) = mpsc::channel();
        let _observer = Observer::install(sender);
        challenge_response::test_support::touch_wait_reports(&[0, 0x80, 0x40]);
        assert!(
            receiver.try_recv().is_err(),
            "fast/non-touch operations must stay silent"
        );
        challenge_response::test_support::touch_wait_reports(&[0x21, 0x21, 0x40]);
        assert_eq!(receiver.try_iter().collect::<Vec<_>>(), [true, false]);
        challenge_response::test_support::touch_wait_reports(&[0x21]);
        assert_eq!(
            receiver.try_iter().collect::<Vec<_>>(),
            [true, false],
            "error/early-return cleanup must clear the prompt"
        );
        challenge_response::test_support::touch_status_outside_response(0x21);
        assert!(
            receiver.try_recv().is_err(),
            "discovery/serial I/O must not display a touch prompt"
        );
    }

    #[test]
    fn touch_wait_is_not_hidden_by_the_write_flag() {
        let (sender, receiver) = mpsc::channel();
        let _observer = Observer::install(sender);
        // The SDK checks RESP_PENDING first, then RESP_TIMEOUT_WAIT. The
        // write flag does not suppress a touch-required keepalive report.
        challenge_response::test_support::touch_wait_reports(&[0xa1]);
        assert_eq!(receiver.try_iter().collect::<Vec<_>>(), [true, false]);
        challenge_response::test_support::touch_wait_reports(&[0x61, 0xe1]);
        assert!(
            receiver.try_recv().is_err(),
            "response data is not a touch wait"
        );
    }
}
