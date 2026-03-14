import { useState } from 'react'
import { FolderSearch, Code2, Shield, Minus, Square, X } from 'lucide-react'
import ScanPage from './pages/ScanPage'
import InjectPage from './pages/InjectPage'
import { cn } from './lib/utils'

type Tab = 'scan' | 'inject'

function App() {
  const [activeTab, setActiveTab] = useState<Tab>('scan')

  // Window controls for frameless window
  const minimizeWindow = () => {
    if (window.runtime?.WindowMinimise) {
      window.runtime.WindowMinimise()
    }
  }

  const maximizeWindow = () => {
    if (window.runtime?.WindowToggleMaximise) {
      window.runtime.WindowToggleMaximise()
    }
  }

  const closeWindow = () => {
    if (window.runtime?.WindowClose) {
      window.runtime.WindowClose()
    }
  }

  // Start window drag - Wails v2 way
  const startDrag = (e: React.MouseEvent) => {
    // Only start drag on left mouse button
    if (e.button === 0 && window.runtime?.WindowStartDrag) {
      window.runtime.WindowStartDrag()
    }
  }

  return (
    <div className="flex h-screen flex-col bg-gray-50 text-gray-900">
      {/* Custom Title Bar - Draggable via WindowStartDrag */}
      <div
        className="flex h-7 items-center justify-between border-b border-gray-200 bg-white px-2 select-none"
        onMouseDown={startDrag}
      >
        <div className="flex items-center gap-1.5">
          <Shield className="h-3.5 w-3.5 text-blue-600" />
          <span className="text-[11px] font-semibold">NoNo</span>
        </div>

        <div className="flex items-center gap-1">
          <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[10px] text-amber-600">
            Security Research
          </span>
        </div>

        {/* Window Controls - stop propagation to prevent drag */}
        <div className="flex items-center" onMouseDown={(e) => e.stopPropagation()}>
          <button
            onClick={minimizeWindow}
            className="flex h-5 w-7 items-center justify-center hover:bg-gray-100"
            title="最小化"
          >
            <Minus className="h-2.5 w-2.5" />
          </button>
          <button
            onClick={maximizeWindow}
            className="flex h-5 w-7 items-center justify-center hover:bg-gray-100"
            title="最大化"
          >
            <Square className="h-2.5 w-2.5" />
          </button>
          <button
            onClick={closeWindow}
            className="flex h-5 w-7 items-center justify-center hover:bg-red-500 hover:text-white"
            title="关闭"
          >
            <X className="h-2.5 w-2.5" />
          </button>
        </div>
      </div>

      {/* Tab Navigation */}
      <nav className="border-b border-gray-200 bg-white">
        <div className="flex gap-0 px-1">
          <button
            onClick={() => setActiveTab('scan')}
            className={cn(
              'flex items-center gap-1 px-2.5 py-1.5 text-[11px] font-medium transition-colors',
              activeTab === 'scan'
                ? 'border-b-2 border-blue-600 text-blue-600'
                : 'text-gray-500 hover:text-gray-700'
            )}
          >
            <FolderSearch className="h-3 w-3" />
            扫描
          </button>
          <button
            onClick={() => setActiveTab('inject')}
            className={cn(
              'flex items-center gap-1 px-2.5 py-1.5 text-[11px] font-medium transition-colors',
              activeTab === 'inject'
                ? 'border-b-2 border-blue-600 text-blue-600'
                : 'text-gray-500 hover:text-gray-700'
            )}
          >
            <Code2 className="h-3 w-3" />
            注入
          </button>
        </div>
      </nav>

      {/* Main Content */}
      <main className="flex-1 overflow-auto p-2">
        {activeTab === 'scan' && <ScanPage />}
        {activeTab === 'inject' && <InjectPage />}
      </main>
    </div>
  )
}

export default App
