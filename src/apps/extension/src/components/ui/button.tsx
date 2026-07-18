import { cva, type VariantProps } from "class-variance-authority";
import type * as React from "react";
import { cn } from "@/lib/cn";

// Control Tower buttons: primary is the SAFE default (Deny is always primary
// in confirmations), danger is kill/deny-with-consequence only, ghost is a
// quiet inline action.
const button = cva(
  "inline-flex items-center justify-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold " +
    "transition-[transform,opacity] cursor-pointer active:scale-97 " +
    "disabled:opacity-40 disabled:cursor-default disabled:active:scale-100 " +
    "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus",
  {
    variants: {
      variant: {
        default: "border border-edge-strong bg-surface-3 text-text-1 hover:bg-surface-4",
        primary: "border border-text-1 bg-text-1 text-surface-0 hover:opacity-90",
        danger:
          "border border-danger-edge bg-transparent text-danger " +
          "hover:bg-danger hover:border-danger hover:text-surface-0",
        ghost:
          "border border-transparent bg-transparent text-text-2 hover:bg-surface-3 hover:text-text-1",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof button> {}

export function Button({ className, variant, type = "button", ...props }: ButtonProps) {
  return <button type={type} className={cn(button({ variant }), className)} {...props} />;
}
