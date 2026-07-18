import { cva, type VariantProps } from "class-variance-authority";
import type * as React from "react";
import { cn } from "@/lib/cn";

// Thin wrapper over the Control Tower .btn classes (styles.css). `gated`
// draws the dashed Touch ID halo; pair it with a <TouchIdChip /> nearby so
// the user can see why the halo is there.
const button = cva("btn", {
  variants: {
    variant: {
      default: "",
      primary: "btn-primary",
      danger: "btn-danger",
      ghost: "btn-ghost",
    },
    size: {
      default: "",
      sm: "btn-sm",
    },
    gated: {
      true: "btn-gated",
      false: "",
    },
  },
  defaultVariants: { variant: "default", size: "default", gated: false },
});

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof button> {}

export function Button({
  className,
  variant,
  size,
  gated,
  type = "button",
  ...props
}: ButtonProps) {
  return (
    <button type={type} className={cn(button({ variant, size, gated }), className)} {...props} />
  );
}
