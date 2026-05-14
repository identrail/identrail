type SkipForNowProps = {
  label?: string;
  disabled?: boolean;
  onSkip: () => void | Promise<void>;
};

export function SkipForNow({ label = 'Skip for now', disabled = false, onSkip }: SkipForNowProps) {
  return (
    <button type="button" className="idt-btn idt-btn-ghost" disabled={disabled} onClick={() => void onSkip()}>
      {label}
    </button>
  );
}
