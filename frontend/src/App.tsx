import { useState } from 'react'
import { FolderSearch, Code2, Shield, Minus, Square, X } from 'lucide-react'
import ScanPage from './pages/ScanPage'
import InjectPage from './pages/InjectPage'
import { cn } from './lib/utils'
import { WindowMinimise, WindowToggleMaximise, Quit } from '../wailsjs/runtime/runtime'
import './lib/wails' // Import for window.runtime type extensions

type Tab = 'scan' | 'inject'

function App() {
  const [activeTab, setActiveTab] = useState<Tab>('scan')
  const [pendingPePath, setPendingPePath] = useState('')

  const handleInjectWithFile = (path: string) => {
    setPendingPePath(path)
    setActiveTab('inject')
  }

  const handlePePathConsumed = () => {
    setPendingPePath('')
  }

  return (
    <div className="flex h-screen flex-col bg-gray-50 text-gray-900">
      {/* Custom Title Bar - uses CSS --wails-draggable for drag */}
      <div className="draggable-title flex h-7 items-center justify-between border-b border-gray-200 bg-white px-2 select-none">
        <div className="flex items-center gap-1.5">
          <Shield className="h-3.5 w-3.5 text-blue-600" />
          <span className="text-[13px] font-semibold">NoNo</span>
        </div>

        <div className="flex items-center gap-1">
          <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[12px] text-amber-600">
            Security Research
          </span>
        </div>

        {/* Window Controls */}
        <div className="flex items-center">
          <button
            onClick={() => WindowMinimise()}
            className="flex h-5 w-7 items-center justify-center hover:bg-gray-100"
            title="最小化"
          >
            <Minus className="h-2.5 w-2.5" />
          </button>
          <button
            onClick={() => WindowToggleMaximise()}
            className="flex h-5 w-7 items-center justify-center hover:bg-gray-100"
            title="最大化"
          >
            <Square className="h-2.5 w-2.5" />
          </button>
          <button
            onClick={() => Quit()}
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
              'flex items-center gap-1 px-2.5 py-1.5 text-[13px] font-medium transition-colors',
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
              'flex items-center gap-1 px-2.5 py-1.5 text-[13px] font-medium transition-colors',
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
        {activeTab === 'scan' && <ScanPage onInjectWithFile={handleInjectWithFile} />}
        {activeTab === 'inject' && <InjectPage pendingPePath={pendingPePath} onPePathConsumed={handlePePathConsumed} />}
      </main>
    </div>
  )
}

export default App
