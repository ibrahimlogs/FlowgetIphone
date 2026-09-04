use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransferState {
    Created,
    Preparing,
    Connecting,
    Transferring,
    Pausing,
    Paused,
    PausedByDisconnect,
    Resuming,
    Cancelling,
    Cancelled,
    Validating,
    Synchronizing,
    Finalizing,
    Completed,
    RecoverableFailure,
    Failed,
}

impl TransferState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Cancelled | Self::Completed | Self::Failed)
    }

    pub fn can_transition_to(self, next: Self) -> bool {
        use TransferState::*;
        matches!(
            (self, next),
            (Created, Preparing | Cancelling | Failed)
                | (Preparing, Connecting | Cancelling | Failed)
                | (
                    Connecting,
                    Transferring | Cancelling | RecoverableFailure | Failed
                )
                | (
                    Transferring,
                    Pausing
                        | PausedByDisconnect
                        | Cancelling
                        | Validating
                        | RecoverableFailure
                        | Failed
                )
                | (Pausing, Paused | Cancelling | RecoverableFailure | Failed)
                | (Paused, Resuming | Cancelling | Cancelled | Failed)
                | (
                    PausedByDisconnect,
                    Resuming | Cancelling | Cancelled | Failed
                )
                | (
                    RecoverableFailure,
                    Resuming | Cancelling | Cancelled | Failed
                )
                | (Cancelled, Resuming)
                | (
                    Resuming,
                    Connecting | Cancelling | RecoverableFailure | Failed
                )
                | (Cancelling, Cancelled | Failed)
                | (
                    Validating,
                    Synchronizing | Cancelling | RecoverableFailure | Failed
                )
                | (
                    Synchronizing,
                    Finalizing | Cancelling | RecoverableFailure | Failed
                )
                | (Finalizing, Completed | RecoverableFailure | Failed)
        ) || self == next
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Lifecycle {
    pub state: TransferState,
    pub generation: u64,
    pub last_state_change_unix_ms: u64,
}

impl Lifecycle {
    pub fn new(now: u64) -> Self {
        Self {
            state: TransferState::Created,
            generation: 0,
            last_state_change_unix_ms: now,
        }
    }

    pub fn transition(&mut self, next: TransferState, now: u64) -> Result<(), String> {
        if !self.state.can_transition_to(next) {
            return Err(format!(
                "invalid native transfer transition: {:?} -> {:?}",
                self.state, next
            ));
        }
        if self.state != next {
            self.state = next;
            self.generation = self
                .generation
                .checked_add(1)
                .ok_or("lifecycle generation overflow")?;
            self.last_state_change_unix_ms = now;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_pause_resume_completion_path() {
        let mut value = Lifecycle::new(1);
        for state in [
            TransferState::Preparing,
            TransferState::Connecting,
            TransferState::Transferring,
            TransferState::Pausing,
            TransferState::Paused,
            TransferState::Resuming,
            TransferState::Connecting,
            TransferState::Transferring,
            TransferState::Validating,
            TransferState::Synchronizing,
            TransferState::Finalizing,
            TransferState::Completed,
        ] {
            value.transition(state, value.generation + 2).unwrap();
        }
        assert_eq!(value.state, TransferState::Completed);
    }

    #[test]
    fn rejects_terminal_and_impossible_transitions() {
        let mut completed = Lifecycle {
            state: TransferState::Completed,
            generation: 9,
            last_state_change_unix_ms: 0,
        };
        assert!(completed
            .transition(TransferState::Transferring, 1)
            .is_err());
        let mut cancelled = Lifecycle {
            state: TransferState::Cancelled,
            generation: 2,
            last_state_change_unix_ms: 0,
        };
        assert!(cancelled.transition(TransferState::Completed, 1).is_err());
        let mut failed = Lifecycle {
            state: TransferState::Failed,
            generation: 2,
            last_state_change_unix_ms: 0,
        };
        assert!(failed.transition(TransferState::Finalizing, 1).is_err());
    }
}
