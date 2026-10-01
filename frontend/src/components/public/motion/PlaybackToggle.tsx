import { Pause, Play } from 'lucide-react';

/** Pause / play for an auto-advancing scene (WCAG 2.2.2). Real button, keyboard reachable, outside any aria-hidden mock. */
export default function PlaybackToggle({ playing, onToggle, label }: { playing: boolean; onToggle: () => void; label: string }) {
  return (
    <button type="button" className="sf-playback" onClick={onToggle} aria-pressed={!playing} aria-label={`${playing ? 'Pause' : 'Play'} ${label}`}>
      {playing ? <Pause size={13} aria-hidden="true" /> : <Play size={13} aria-hidden="true" />}
      <span>{playing ? 'Pause' : 'Play'}</span>
    </button>
  );
}
