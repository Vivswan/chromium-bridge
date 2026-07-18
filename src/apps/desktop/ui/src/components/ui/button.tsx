import { cva, type VariantProps } from "class-variance-authority";
import type * as React from "react";
import { cn } from "@/lib/cn";

const button = cva(
  "inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold " +
    "transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-default " +
    "focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-brand",
  {
    variants: {
      variant: {
        default: "border border-edge bg-surface text-body hover:bg-edge-soft",
        primary: "border border-brand bg-brand text-white hover:bg-brand-strong",
        danger: "border border-danger bg-danger text-white hover:bg-danger-strong",
        ghost: "border border-transparent bg-transparent text-danger hover:bg-danger-surface",
      },
      size: {
        default: "",
        sm: "px-3 py-1 text-xs",
      },
    },
    defaultVariants: { variant: "default", size: "default" },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof button> {}

export function Button({ className, variant, size, type = "button", ...props }: ButtonProps) {
  return <button type={type} className={cn(button({ variant, size }), className)} {...props} />;
}
