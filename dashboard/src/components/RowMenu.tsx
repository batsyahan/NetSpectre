import { useEffect, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { IconEllipsis } from "./icons";

export interface MenuItem {
  label: string;
  onSelect: () => void;
}

// Overflow menu for a table row. Positioned with `fixed` so a scrolling table never clips it.
export function RowMenu({ label, items }: { label: string; items: MenuItem[] }) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top?: number; bottom?: number; right: number }>({ right: 0 });
  const button = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLDivElement>(null);

  const toggle = () => {
    if (open) {
      setOpen(false);
      return;
    }
    const r = button.current?.getBoundingClientRect();
    if (!r) return;
    const right = window.innerWidth - r.right;
    const room = window.innerHeight - r.bottom;
    setPos(room < items.length * 40 + 16 ? { bottom: window.innerHeight - r.top + 4, right } : { top: r.bottom + 4, right });
    setOpen(true);
  };

  useEffect(() => {
    if (!open) return;
    const close = () => setOpen(false);
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node;
      if (menu.current?.contains(t) || button.current?.contains(t)) return;
      close();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        close();
        button.current?.focus();
      }
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);
    menu.current?.querySelector<HTMLButtonElement>("button")?.focus();
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("resize", close);
    };
  }, [open]);

  const onMenuKey = (e: ReactKeyboardEvent<HTMLDivElement>) => {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const els = [...(menu.current?.querySelectorAll<HTMLButtonElement>("button") ?? [])];
    const i = els.indexOf(document.activeElement as HTMLButtonElement);
    const next = e.key === "ArrowDown" ? (i + 1) % els.length : (i - 1 + els.length) % els.length;
    els[next]?.focus();
  };

  return (
    <>
      <button
        ref={button}
        type="button"
        className="icon-btn"
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={toggle}
      >
        <IconEllipsis size={18} />
      </button>
      {open && (
        <div ref={menu} role="menu" className="menu" style={pos} onKeyDown={onMenuKey}>
          {items.map((it) => (
            <button
              key={it.label}
              type="button"
              role="menuitem"
              onClick={() => {
                setOpen(false);
                it.onSelect();
              }}
            >
              {it.label}
            </button>
          ))}
        </div>
      )}
    </>
  );
}
