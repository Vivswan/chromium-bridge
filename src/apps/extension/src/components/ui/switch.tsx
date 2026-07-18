import * as SwitchPrimitive from "@radix-ui/react-switch";
import type * as React from "react";
import { cn } from "@/lib/cn";

// Control Tower switch: neutral control track; the on state speaks in the
// live green (signal color, never decorative elsewhere).
export function Switch({ className, ...props }: React.ComponentProps<typeof SwitchPrimitive.Root>) {
  return (
    <SwitchPrimitive.Root
      className={cn(
        "peer relative inline-flex h-[17px] w-[30px] shrink-0 cursor-pointer items-center rounded-full border " +
          "transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 " +
          "focus-visible:outline-focus disabled:cursor-default disabled:opacity-45 " +
          "border-edge-strong bg-surface-4 data-[state=checked]:border-live-edge data-[state=checked]:bg-live-dim",
        className,
      )}
      {...props}
    >
      <SwitchPrimitive.Thumb
        className={cn(
          "pointer-events-none block size-[11px] rounded-full bg-text-3 transition-transform " +
            "data-[state=checked]:translate-x-[15px] data-[state=checked]:bg-live data-[state=unchecked]:translate-x-[2px]",
        )}
      />
    </SwitchPrimitive.Root>
  );
}
