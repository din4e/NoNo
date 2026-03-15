import { useState, useEffect, useCallback, useMemo } from 'react'
import {
  FolderOpen,
  Play,
  Square,
  Loader2,
  FileCheck,
  FileX,
  Cpu,
  HardDrive,
  File,
  ChevronDown,
  ChevronRight,
  Filter,
  X,
} from 'lucide-react'
import {
  SelectDirectory,
  StartScan,
  StopScan,
  GetDefaultConfig,
  EventsOn,
  EventsOff,
} from '../lib/wails'
import type { FileInfo, ScanProgress, ScanConfig } from '../lib/wails'
import { cn, formatSize, truncatePath } from '../lib/utils'

function ScanPage() {
  const [directory, setDirectory] = useState('')
  const [minSize, setMinSize] = useState(0)
  const [maxSize, setMaxSize] = useState(61440)
  const [architecture, setArchitecture] = useState('x64')
  const [signFilter, setSignFilter] = useState('signed')
  const [extensions, setExtensions] = useState('exe')
  const [workers, setWorkers] = useState(4)
  const [isScanning, setIsScanning] = useState(false)
  const [progress, setProgress] = useState<ScanProgress>({
    totalFiles: 0,
    scannedFiles: 0,
    foundFiles: 0,
    isScanning: false,
  })
  const [results, setResults] = useState<FileInfo[]>([])
  const [selectedFile, setSelectedFile] = useState<FileInfo | null>(null)
  const [expandedSections, setExpandedSections] = useState({
    config: true,
    results: true,
  })

  // Filter state
  const [filterText, setFilterText] = useState('')
  const [filterSigned, setFilterSigned] = useState<'all' | 'signed' | 'unsigned'>('all')
  const [filterArch, setFilterArch] = useState<'all' | 'x64' | 'x86'>('all')
  const [showFilter, setShowFilter] = useState(false)

  // Filtered results
  const filteredResults = useMemo(() => {
    return results.filter((file) => {
      // Text filter
      if (filterText && !file.path.toLowerCase().includes(filterText.toLowerCase())) {
        return false
      }
      // Signed filter
      if (filterSigned === 'signed' && !file.isSigned) return false
      if (filterSigned === 'unsigned' && file.isSigned) return false
      // Arch filter
      if (filterArch !== 'all' && file.architecture !== filterArch) return false
      return true
    })
  }, [results, filterText, filterSigned, filterArch])

  const hasActiveFilters = filterText || filterSigned !== 'all' || filterArch !== 'all'

  const clearFilters = () => {
    setFilterText('')
    setFilterSigned('all')
    setFilterArch('all')
  }

  useEffect(() => {
    GetDefaultConfig().then((cfg) => {
      setDirectory(cfg.defaultScanDir || 'C:\\Program Files\\')
      setMinSize(cfg.defaultMinSize || 0)
      setMaxSize(cfg.defaultMaxSize || 61440)
      setArchitecture(cfg.defaultArch || 'x64')
      setSignFilter(cfg.defaultSignFilter || 'signed')
      setWorkers(cfg.defaultWorkers || 4)
    })

    EventsOn('scan:progress', (data) => setProgress(data as ScanProgress))
    EventsOn('scan:result', (data) => setResults((prev) => [...prev, data as FileInfo]))
    EventsOn('scan:complete', () => setIsScanning(false))
    EventsOn('scan:error', (err) => {
      console.error('Scan error:', err)
      setIsScanning(false)
    })

    return () => {
      EventsOff('scan:progress')
      EventsOff('scan:result')
      EventsOff('scan:complete')
      EventsOff('scan:error')
    }
  }, [])

  const handleSelectDirectory = useCallback(async () => {
    try {
      const dir = await SelectDirectory()
      if (dir) setDirectory(dir)
    } catch (e) {
      console.error('Select directory failed:', e)
    }
  }, [])

  const handleStartScan = useCallback(async () => {
    if (!directory) return
    setResults([])
    setSelectedFile(null)
    setIsScanning(true)

    const cfg: ScanConfig = {
      directory,
      minSize,
      maxSize,
      architecture,
      extensions: extensions.split(',').map((e) => e.trim()),
      workers,
      signFilter,
      showImports: true,
    }

    try {
      await StartScan(cfg)
    } catch (e) {
      console.error('Start scan failed:', e)
      setIsScanning(false)
    }
  }, [directory, minSize, maxSize, architecture, extensions, workers, signFilter])

  const handleStopScan = useCallback(async () => {
    await StopScan()
    setIsScanning(false)
  }, [])

  const toggleSection = (section: 'config' | 'results') => {
    setExpandedSections((prev) => ({ ...prev, [section]: !prev[section] }))
  }

  return (
    <div className="flex h-full flex-col gap-2">
      {/* Config Section */}
      <div className="rounded border border-gray-200 bg-white">
        <button
          onClick={() => toggleSection('config')}
          className="flex w-full items-center justify-between px-2 py-1.5 hover:bg-gray-50"
        >
          <span className="text-xs font-medium">扫描配置</span>
          {expandedSections.config ? (
            <ChevronDown className="h-3 w-3 text-gray-400" />
          ) : (
            <ChevronRight className="h-3 w-3 text-gray-400" />
          )}
        </button>

        {expandedSections.config && (
          <div className="border-t border-gray-100 px-2 pb-2 pt-1.5">
            <div className="grid grid-cols-6 gap-2">
              {/* Directory */}
              <div className="col-span-6">
                <div className="flex gap-1">
                  <input
                    type="text"
                    value={directory}
                    onChange={(e) => setDirectory(e.target.value)}
                    className="flex-1 rounded border border-gray-300 px-2 py-1 text-xs focus:border-blue-500 focus:outline-none"
                    placeholder="扫描目录..."
                  />
                  <button
                    onClick={handleSelectDirectory}
                    className="flex items-center gap-1 rounded border border-gray-300 px-2 py-1 text-xs hover:bg-gray-50"
                  >
                    <FolderOpen className="h-3 w-3" />
                  </button>
                </div>
              </div>

              {/* Size Range */}
              <div className="col-span-2">
                <label className="mb-0.5 block text-[10px] text-gray-500">最小大小</label>
                <input
                  type="number"
                  value={minSize}
                  onChange={(e) => setMinSize(Number(e.target.value))}
                  className="w-full rounded border border-gray-300 px-2 py-1 text-xs focus:border-blue-500 focus:outline-none"
                />
              </div>
              <div className="col-span-2">
                <label className="mb-0.5 block text-[10px] text-gray-500">最大大小</label>
                <input
                  type="number"
                  value={maxSize}
                  onChange={(e) => setMaxSize(Number(e.target.value))}
                  className="w-full rounded border border-gray-300 px-2 py-1 text-xs focus:border-blue-500 focus:outline-none"
                />
              </div>
              <div className="col-span-2">
                <label className="mb-0.5 block text-[10px] text-gray-500">线程数</label>
                <input
                  type="number"
                  value={workers}
                  onChange={(e) => setWorkers(Number(e.target.value))}
                  min={1}
                  max={32}
                  className="w-full rounded border border-gray-300 px-2 py-1 text-xs focus:border-blue-500 focus:outline-none"
                />
              </div>

              {/* Architecture & Sign Filter & Extensions */}
              <div className="col-span-2">
                <label className="mb-0.5 block text-[10px] text-gray-500">架构</label>
                <select
                  value={architecture}
                  onChange={(e) => setArchitecture(e.target.value)}
                  className="w-full rounded border border-gray-300 px-2 py-1 text-xs focus:border-blue-500 focus:outline-none"
                >
                  <option value="x64">x64</option>
                  <option value="x86">x86</option>
                  <option value="both">全部</option>
                </select>
              </div>
              <div className="col-span-2">
                <label className="mb-0.5 block text-[10px] text-gray-500">签名</label>
                <select
                  value={signFilter}
                  onChange={(e) => setSignFilter(e.target.value)}
                  className="w-full rounded border border-gray-300 px-2 py-1 text-xs focus:border-blue-500 focus:outline-none"
                >
                  <option value="signed">已签名</option>
                  <option value="unsigned">未签名</option>
                  <option value="all">全部</option>
                </select>
              </div>
              <div className="col-span-2">
                <label className="mb-0.5 block text-[10px] text-gray-500">扩展名</label>
                <input
                  type="text"
                  value={extensions}
                  onChange={(e) => setExtensions(e.target.value)}
                  className="w-full rounded border border-gray-300 px-2 py-1 text-xs focus:border-blue-500 focus:outline-none"
                  placeholder="exe,dll"
                />
              </div>

              {/* Actions & Progress */}
              <div className="col-span-6 flex items-end gap-2">
                <div className="flex-1">
                  {isScanning && (
                    <div className="flex items-center gap-2">
                      <div className="flex-1">
                        <div className="flex items-center justify-between text-[10px] text-gray-500">
                          <span>{progress.scannedFiles} / {progress.totalFiles}</span>
                          <span className="text-green-600">+{progress.foundFiles}</span>
                        </div>
                        <div className="mt-0.5 h-1.5 overflow-hidden rounded-full bg-gray-200">
                          <div
                            className="h-full bg-blue-500 transition-all"
                            style={{
                              width: progress.totalFiles > 0
                                ? `${(progress.scannedFiles / progress.totalFiles) * 100}%`
                                : '0%',
                            }}
                          />
                        </div>
                      </div>
                    </div>
                  )}
                </div>
                {isScanning ? (
                  <button
                    onClick={handleStopScan}
                    className="flex items-center gap-1 rounded bg-red-500 px-3 py-1.5 text-xs text-white hover:bg-red-600"
                  >
                    <Square className="h-3 w-3" />
                    停止
                  </button>
                ) : (
                  <button
                    onClick={handleStartScan}
                    className="flex items-center gap-1 rounded bg-blue-500 px-3 py-1.5 text-xs text-white hover:bg-blue-600"
                  >
                    <Play className="h-3 w-3" />
                    扫描
                  </button>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Results Section */}
      <div className="flex-1 overflow-hidden rounded border border-gray-200 bg-white">
        <button
          onClick={() => toggleSection('results')}
          className="flex w-full items-center justify-between px-2 py-1.5 hover:bg-gray-50"
        >
          <span className="text-xs font-medium">
            扫描结果 ({hasActiveFilters ? `${filteredResults.length}/${results.length}` : results.length})
          </span>
          <div className="flex items-center gap-1">
            {hasActiveFilters && (
              <span className="rounded bg-blue-100 px-1 py-0.5 text-[10px] text-blue-600">
                已过滤
              </span>
            )}
            {expandedSections.results ? (
              <ChevronDown className="h-3 w-3 text-gray-400" />
            ) : (
              <ChevronRight className="h-3 w-3 text-gray-400" />
            )}
          </div>
        </button>

        {expandedSections.results && (
          <div className="flex h-[calc(100%-32px)] flex-col border-t border-gray-100">
            {/* Filter Bar */}
            <div className="flex items-center gap-1 border-b border-gray-100 px-2 py-1">
              <button
                onClick={() => setShowFilter(!showFilter)}
                className={cn(
                  'flex items-center gap-0.5 rounded px-1.5 py-0.5 text-[10px]',
                  showFilter || hasActiveFilters
                    ? 'bg-blue-100 text-blue-600'
                    : 'text-gray-500 hover:bg-gray-100'
                )}
              >
                <Filter className="h-2.5 w-2.5" />
                过滤
              </button>
              {hasActiveFilters && (
                <button
                  onClick={clearFilters}
                  className="flex items-center gap-0.5 rounded px-1.5 py-0.5 text-[10px] text-gray-500 hover:bg-gray-100"
                >
                  <X className="h-2.5 w-2.5" />
                  清除
                </button>
              )}
              {showFilter && (
                <>
                  <input
                    type="text"
                    value={filterText}
                    onChange={(e) => setFilterText(e.target.value)}
                    placeholder="搜索文件名..."
                    className="ml-1 w-32 rounded border border-gray-200 px-1.5 py-0.5 text-[10px] focus:border-blue-500 focus:outline-none"
                  />
                  <select
                    value={filterSigned}
                    onChange={(e) => setFilterSigned(e.target.value as 'all' | 'signed' | 'unsigned')}
                    className="rounded border border-gray-200 px-1.5 py-0.5 text-[10px] focus:border-blue-500 focus:outline-none"
                  >
                    <option value="all">全部签名</option>
                    <option value="signed">已签名</option>
                    <option value="unsigned">未签名</option>
                  </select>
                  <select
                    value={filterArch}
                    onChange={(e) => setFilterArch(e.target.value as 'all' | 'x64' | 'x86')}
                    className="rounded border border-gray-200 px-1.5 py-0.5 text-[10px] focus:border-blue-500 focus:outline-none"
                  >
                    <option value="all">全部架构</option>
                    <option value="x64">x64</option>
                    <option value="x86">x86</option>
                  </select>
                </>
              )}
            </div>

            {/* Results Content */}
            <div className="flex flex-1 overflow-hidden">
              {/* Results List */}
              <div className={cn(
                'flex flex-col border-r border-gray-100 transition-all',
                selectedFile ? 'w-1/2' : 'flex-1'
              )}>
              {results.length === 0 ? (
                <div className="flex flex-1 items-center justify-center text-xs text-gray-400">
                  {isScanning ? (
                    <div className="flex items-center gap-1">
                      <Loader2 className="h-3 w-3 animate-spin" />
                      扫描中...
                    </div>
                  ) : (
                    <div className="text-center">
                      <File className="mx-auto mb-1 h-6 w-6 text-gray-300" />
                      <p>配置参数后点击扫描</p>
                    </div>
                  )}
                </div>
              ) : (
                <div className="flex-1 overflow-auto">
                  <table className="w-full text-[11px]">
                    <thead className="sticky top-0 z-10 bg-white">
                      <tr className="border-b border-gray-100 text-left text-gray-500">
                        <th className="pb-1 font-medium">文件</th>
                        <th className="pb-1 font-medium">大小</th>
                        <th className="pb-1 font-medium">架构</th>
                        <th className="pb-1 font-medium">签名</th>
                        <th className="pb-1 font-medium">导入</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredResults.map((file, idx) => (
                        <tr
                          key={idx}
                          onClick={() => setSelectedFile(file)}
                          className={cn(
                            'cursor-pointer border-b border-gray-50 hover:bg-blue-50',
                            selectedFile?.path === file.path && 'bg-blue-100 hover:bg-blue-100'
                          )}
                        >
                          <td className="py-1" title={file.path}>
                            {truncatePath(file.path, 28)}
                          </td>
                          <td className="py-1">
                            <span className="flex items-center gap-0.5 text-gray-500">
                              <HardDrive className="h-2.5 w-2.5" />
                              {formatSize(file.size)}
                            </span>
                          </td>
                          <td className="py-1">
                            <span className="flex items-center gap-0.5 text-gray-500">
                              <Cpu className="h-2.5 w-2.5" />
                              {file.architecture}
                            </span>
                          </td>
                          <td className="py-1">
                            {file.isSigned ? (
                              <span className="flex items-center gap-0.5 text-green-600">
                                <FileCheck className="h-2.5 w-2.5" />
                                {file.signerInfo ? '✓' : '✓'}
                              </span>
                            ) : (
                              <span className="flex items-center gap-0.5 text-red-500">
                                <FileX className="h-2.5 w-2.5" />
                              </span>
                            )}
                          </td>
                          <td className="py-1 text-gray-500">
                            {file.importCount}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* File Details */}
            {selectedFile && (
              <div className="flex w-1/2 flex-col overflow-auto p-2">
                <div className="mb-2 flex items-center justify-between">
                  <span className="text-xs font-medium">文件详情</span>
                  <button
                    onClick={() => setSelectedFile(null)}
                    className="text-[10px] text-gray-400 hover:text-gray-600"
                  >
                    关闭
                  </button>
                </div>

                <div className="space-y-1.5 text-[11px]">
                  {/* Path */}
                  <div className="rounded bg-gray-50 p-1.5">
                    <div className="mb-0.5 text-[10px] text-gray-400">完整路径</div>
                    <div className="break-all">{selectedFile.path}</div>
                  </div>

                  {/* Basic Info Grid */}
                  <div className="grid grid-cols-3 gap-1">
                    <div className="rounded bg-gray-50 p-1.5">
                      <div className="text-[10px] text-gray-400">大小</div>
                      <div className="font-medium">{formatSize(selectedFile.size)}</div>
                    </div>
                    <div className="rounded bg-gray-50 p-1.5">
                      <div className="text-[10px] text-gray-400">架构</div>
                      <div className="font-medium">{selectedFile.architecture}</div>
                    </div>
                    <div className="rounded bg-gray-50 p-1.5">
                      <div className="text-[10px] text-gray-400">签名</div>
                      <div className={cn('font-medium', selectedFile.isSigned ? 'text-green-600' : 'text-red-500')}>
                        {selectedFile.isSigned ? '已签名' : '未签名'}
                      </div>
                    </div>
                  </div>

                  {/* Signer Info */}
                  {selectedFile.isSigned && selectedFile.signerInfo && (
                    <div className="rounded bg-green-50 p-1.5">
                      <div className="text-[10px] text-green-600">签名者</div>
                      <div className="text-green-700">{selectedFile.signerInfo}</div>
                    </div>
                  )}

                  {/* Import Stats */}
                  <div className="rounded bg-gray-50 p-1.5">
                    <div className="flex items-center justify-between">
                      <div className="text-[10px] text-gray-400">导入表</div>
                      <div className="text-[10px]">
                        {selectedFile.importCount} 函数 / {selectedFile.importedDLLs.length} DLL
                      </div>
                    </div>
                  </div>

                  {/* DLL List */}
                  {selectedFile.importedDLLs.length > 0 && (
                    <div className="flex-1 overflow-auto rounded border border-gray-200 bg-white">
                      <div className="sticky top-0 bg-gray-50 px-1.5 py-1 text-[10px] font-medium text-gray-500">
                        DLL 列表
                      </div>
                      <div className="max-h-32 overflow-auto">
                        {selectedFile.importedDLLs.map((dll, i) => (
                          <div
                            key={i}
                            className="flex items-center justify-between border-b border-gray-50 px-1.5 py-0.5 text-[10px]"
                          >
                            <span className="font-mono text-blue-600">{dll.dllName}</span>
                            <span className="text-gray-400">{dll.functions.length} 函数</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default ScanPage
