impl BootstrapStateStore {
    /// Return the machine-scoped external monotonic-anchor path that must travel
    /// with an explicitly authorized recovery checkpoint. Normal bootstrap state
    /// never stores this path inside its rollback domain.
    pub fn recovery_anchor_path(&self) -> Result<PathBuf, DurableBootstrapError> {
        self.generation_anchor_path()
    }
}
