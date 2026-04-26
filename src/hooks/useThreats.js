import { useContext } from 'react'
import { ThreatContext } from '../context/ThreatContext'

export const useThreats = () => {
  const context = useContext(ThreatContext)
  if (!context) {
    throw new Error('useThreats must be used inside ThreatProvider')
  }
  return context
}
