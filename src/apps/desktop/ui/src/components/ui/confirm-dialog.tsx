import * as DialogPrimitive from "@radix-ui/react-dialog";
import type * as React from "react";
import { useEffect, useRef } from "react";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/hooks/useI18n";

// The app-owned explicit confirmation for capability-granting acts (unkill,
// add-client). This modal is LOAD-BEARING, not cosmetic: with
// Floor::AppConfirm, the presence call succeeds by construction when
// hardware is unavailable, on the assertion that the app already showed
// exactly this dialog. The confirm handler is therefore the only place the
// presence-gated Tauri commands may be invoked from.
//
// Control Tower law: the safe default is the primary button, so CANCEL is
// primary here; the capability-granting confirm is a plain gated button
// (the dashed halo says a Touch ID prompt may follow).
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  body,
  confirmLabel,
  busy,
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  body: React.ReactNode;
  confirmLabel: string;
  busy: boolean;
  onConfirm: () => void;
}) {
  const { t } = useI18n();
  // Synchronous single-flight: `busy` only disables the button after a
  // rerender, so two clicks in one frame could fire the command (and stack
  // Touch ID prompts). The ref blocks the second call immediately; it
  // re-arms each time the dialog opens.
  const fired = useRef(false);
  useEffect(() => {
    if (open) fired.current = false;
  }, [open]);
  return (
    <DialogPrimitive.Root open={open} onOpenChange={(next) => !busy && onOpenChange(next)}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="dialog-overlay fixed inset-0 z-40 bg-black/50" />
        <DialogPrimitive.Content
          className="dialog-content fixed left-1/2 top-1/2 z-50 w-96 max-w-[90vw]
            rounded-lg border border-edge-strong bg-surface-2 p-4"
        >
          <DialogPrimitive.Title className="m-0 text-[13px] font-semibold text-text-1">
            {title}
          </DialogPrimitive.Title>
          <DialogPrimitive.Description asChild>
            <div className="consequence mt-2">{body}</div>
          </DialogPrimitive.Description>
          <div className="mt-4 flex justify-end gap-2">
            <DialogPrimitive.Close asChild>
              <Button variant="primary" disabled={busy}>
                {t("common.cancel")}
              </Button>
            </DialogPrimitive.Close>
            <Button
              gated
              pending={busy}
              disabled={busy}
              onClick={() => {
                if (fired.current || busy) return;
                fired.current = true;
                onConfirm();
              }}
            >
              {busy ? t("common.working") : confirmLabel}
            </Button>
          </div>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}
