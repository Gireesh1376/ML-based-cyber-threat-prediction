import type { ReactNode } from 'react'
import { useScrollReveal } from '../hooks/useScrollReveal'

interface ScrollSectionProps {
  children: ReactNode
  className?: string
  delay?: number
  threshold?: number
}

export function ScrollSection({ 
  children, 
  className = '', 
  delay = 0,
  threshold = 0.08 
}: ScrollSectionProps) {
  const [ref, isVisible] = useScrollReveal(threshold)

  return (
    <div
      ref={ref}
      style={{ transitionDelay: `${delay}ms` }}
      className={`reveal-on-scroll ${isVisible ? 'is-revealed' : ''} ${className}`}
    >
      {children}
    </div>
  )
}
