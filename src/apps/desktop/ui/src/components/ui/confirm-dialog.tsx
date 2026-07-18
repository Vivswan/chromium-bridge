import * as DialogPrimitive from "@radix-ui/react-dialog";
import type * as React from "react";
import { useEffect, useRef } from "react";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/hooks/useI18n";

// The app-owned explicit confirmation for capability-granting acts (unkill,
// add-client). This modal is LOAD-BEARING, not cosmetic: with Phase 8's
// Floor::AppConfirm, the presence call succeeds by construction when
// hardware is unavailable, on the assertion that the app already showed
// exactly this dialog. The confirm handler is therefore the only place the
// presence-gated Tauri commands may be invoked from.
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
  // rerender, so two clicks in one frame could fire the command (and, post
  // Phase 8, stack Touch ID prompts). The ref blocks the second call
  // immediately; it re-arms each time the dialog opens.
  const fired = useRef(false);
  useEffect(() => {
    if (open) fired.current = false;
  }, [open]);
  return (
    <DialogPrimitive.Root open={open} onOpenChange={(next) => !busy && onOpenChange(next)}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-black/40" />
        <DialogPrimitive.Content
          className="fixed left-1/2 top-1/2 z-50 w-96 max-w-[90vw] -translate-x-1/2 -translate-y-1/2
            rounded-xl border border-edge bg-surface p-4 shadow-xl focus:outline-none"
        >
          <DialogPrimitive.Title className="m-0 text-sm font-semibold text-body">
            {title}
          </DialogPrimitive.Title>
          <DialogPrimitive.Description asChild>
            <div className="mt-2 text-sm text-muted">{body}</div>
          </DialogPrimitive.Description>
          <div className="mt-4 flex justify-end gap-2">
            <DialogPrimitive.Close asChild>
              <Button disabled={busy}>{t("common.cancel")}</Button>
            </DialogPrimitive.Close>
            <Button
              variant="primary"
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
