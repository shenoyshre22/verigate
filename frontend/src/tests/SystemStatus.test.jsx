
import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import SystemStatus from '../components/SystemStatus'

describe('SystemStatus', () => {
  it('displays ONLINE when connected', () => {
    render(<SystemStatus online={true} />)

    expect(screen.getByTestId('system-status'))
      .toHaveTextContent('ONLINE')
  })

  it('displays OFFLINE when disconnected', () => {
    render(<SystemStatus online={false} />)

    expect(screen.getByTestId('system-status'))
      .toHaveTextContent('OFFLINE')
  })
})
