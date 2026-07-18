import * as SwitchPrimitive from "@radix-ui/react-switch";
import type * as React from "react";
import { cn } from "@/lib/cn";

// Control Tower switch: a plain control in BOTH positions, macOS-style - the
// checked state fills the track with neutral ink, never the live green
// (green = live+attested status only; a settings toggle is configuration,
// and many toggles here ENABLE risk). The ::before inset pads the hit target
// to ~41x54px without changing the visual size (WCAG 2.5.8 / project bar).
export function Switch({ className, ...props }: React.ComponentProps<typeof SwitchPrimitive.Root>) {
  return (
    <SwitchPrimitive.Root
      className={cn(
        "peer relative inline-flex h-[17px] w-[30px] shrink-0 cursor-pointer items-center rounded-full border " +
          "before:absolute before:-inset-3 before:content-[''] " +
          "transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 " +
          "focus-visible:outline-focus disabled:cursor-default disabled:opacity-45 " +
          "border-edge-strong bg-surface-4 data-[state=checked]:border-text-1 data-[state=checked]:bg-text-1",
        className,
      )}
      {...props}
    >
      <SwitchPrimitive.Thumb
        className={cn(
          "pointer-events-none block size-[11px] rounded-full bg-text-3 transition-transform " +
            "data-[state=checked]:translate-x-[15px] data-[state=checked]:bg-surface-0 data-[state=unchecked]:translate-x-[2px]",
        )}
      />
    </SwitchPrimitive.Root>
  );
}
