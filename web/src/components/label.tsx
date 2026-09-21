import { cn } from "@/lib/utils"
export function Label({ className, ...props }: React.ComponentProps<"label">) {
  return <label className={cn("flex items-center gap-1.5 text-xs text-foreground/80", className)} {...props} />
}
