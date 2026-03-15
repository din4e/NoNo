import { useState, useCallback, useEffect } from 'react'
import {
  FileCode,
  FileUp,
  Play,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Loader2,
  ChevronDown,
  ChevronRight,
  Cpu,
  HardDrive,
  FileCheck,
  FileX,
} from 'lucide-react'
import {
  SelectPEFile,
  SelectShellcodeFile,
  Inject,
  GetPEInfo,
  GetTemplates,
} from '../lib/wails'
import type { InjectConfig, PEInfo, InjectResult, TemplateInfo } from '../lib/wails'
import { cn, formatSize } from '../lib/utils'

function InjectPage() {
  const [pePath, setPePath] = useState('')
  const [shellcodePath, setShellcodePath] = useState('')
  const [method, setMethod] = useState('function')
  const [preserveSig, setPreserveSig] = useState(false)
  const [funcName, setFuncName] = useState('')
  const [backup, setBackup] = useState(true)
  const [peInfo, setPeInfo] = useState<PEInfo | null>(null)
  const [result, setResult] = useState<InjectResult | null>(null)
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [isInjecting, setIsInjecting] = useState(false)
  const [selectedTemplate, setSelectedTemplate] = useState<string>('')
  const [templates, setTemplates] = useState<TemplateInfo[]>([])
  const [expandedSections, setExpandedSections] = useState({
    peFile: true,
    shellcode: true,
    options: true,
  })

  useEffect(() => {
    loadTemplates()
  }, [])

  const loadTemplates = async () => {
    try {
      const tpls = await GetTemplates()
      setTemplates(tpls || [])
    } catch (e) {
      console.error('Failed to load templates:', e)
      // Don't block - just set empty templates
    }
  }

  const handleSelectPE = useCallback(async () => {
    try {
      setIsLoading(true)
      const path = await SelectPEFile()
      if (path) {
        setPePath(path)
        try {
          const info = await GetPEInfo(path)
          setPeInfo(info)
        } catch (e) {
          console.error('Failed to get PE info:', e)
        }
      }
    } catch (e) {
      console.error('Failed to select PE file:', e)
    } finally {
      setIsLoading(false)
    }
  }, [])

  const handleSelectShellcode = useCallback(async () => {
    try {
      const path = await SelectShellcodeFile()
      if (path) {
        setShellcodePath(path)
        setSelectedTemplate('')
      }
    } catch (e) {
      console.error('Failed to select shellcode file:', e)
    }
  }, [])

  const handleTemplateSelect = (path: string) => {
    if (path) {
      setSelectedTemplate(path)
      setShellcodePath(path)
    } else {
      setSelectedTemplate('')
      setShellcodePath('')
    }
  }

  const handleInject = useCallback(async () => {
    if (!pePath || !shellcodePath) {
      setError('请选择目标 PE 文件和 Shellcode')
      return
    }

    setError('')
    setResult(null)
    setIsInjecting(true)

    const cfg: InjectConfig = {
      pePath,
      shellcodePath,
      method,
      preserveSig,
      funcName,
      backup,
    }

    try {
      const res = await Inject(cfg)
      setResult(res)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setIsInjecting(false)
    }
  }, [pePath, shellcodePath, method, preserveSig, funcName, backup])

  const toggleSection = (section: 'peFile' | 'shellcode' | 'options') => {
    setExpandedSections((prev) => ({ ...prev, [section]: !prev[section] }))
  }

  return (
    <div className="flex h-full flex-col gap-2">
      {/* PE File Section */}
      <div className="rounded border border-gray-200 bg-white">
        <button
          onClick={() => toggleSection('peFile')}
          className="flex w-full items-center justify-between px-2 py-1.5 hover:bg-gray-50"
        >
          <span className="text-xs font-medium">目标 PE 文件</span>
          {expandedSections.peFile ? (
            <ChevronDown className="h-3 w-3 text-gray-400" />
          ) : (
            <ChevronRight className="h-3 w-3 text-gray-400" />
          )}
        </button>

        {expandedSections.peFile && (
          <div className="border-t border-gray-100 px-2 pb-2 pt-1.5">
            <div className="flex gap-1">
              <input
                type="text"
                value={pePath}
                onChange={(e) => setPePath(e.target.value)}
                className="flex-1 rounded border border-gray-300 px-2 py-1 text-xs focus:border-blue-500 focus:outline-none"
                placeholder="选择可执行文件..."
              />
              <button
                onClick={handleSelectPE}
                disabled={isLoading}
                className="flex items-center gap-1 rounded border border-gray-300 px-2 py-1 text-xs hover:bg-gray-50 disabled:opacity-50"
              >
                {isLoading ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <FileCode className="h-3 w-3" />
                )}
                浏览
              </button>
            </div>

            {/* PE Info Grid */}
            {peInfo && (
              <div className="mt-1.5 grid grid-cols-4 gap-1 text-[11px]">
                <div className="rounded bg-gray-50 p-1.5">
                  <div className="text-[10px] text-gray-400">大小</div>
                  <div className="flex items-center gap-0.5 font-medium">
                    <HardDrive className="h-2.5 w-2.5 text-gray-400" />
                    {formatSize(peInfo.size)}
                  </div>
                </div>
                <div className="rounded bg-gray-50 p-1.5">
                  <div className="text-[10px] text-gray-400">架构</div>
                  <div className="flex items-center gap-0.5 font-medium">
                    <Cpu className="h-2.5 w-2.5 text-gray-400" />
                    {peInfo.architecture}
                  </div>
                </div>
                <div className="rounded bg-gray-50 p-1.5">
                  <div className="text-[10px] text-gray-400">类型</div>
                  <div className="font-medium">{peInfo.isDll ? 'DLL' : 'EXE'}</div>
                </div>
                <div className="rounded bg-gray-50 p-1.5">
                  <div className="text-[10px] text-gray-400">签名</div>
                  <div className={cn('flex items-center gap-0.5 font-medium', peInfo.isSigned ? 'text-green-600' : 'text-red-500')}>
                    {peInfo.isSigned ? <FileCheck className="h-2.5 w-2.5" /> : <FileX className="h-2.5 w-2.5" />}
                    {peInfo.isSigned ? '有' : '无'}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Shellcode Section */}
      <div className="rounded border border-gray-200 bg-white">
        <button
          onClick={() => toggleSection('shellcode')}
          className="flex w-full items-center justify-between px-2 py-1.5 hover:bg-gray-50"
        >
          <span className="text-xs font-medium">Shellcode</span>
          {expandedSections.shellcode ? (
            <ChevronDown className="h-3 w-3 text-gray-400" />
          ) : (
            <ChevronRight className="h-3 w-3 text-gray-400" />
          )}
        </button>

        {expandedSections.shellcode && (
          <div className="border-t border-gray-100 px-2 pb-2 pt-1.5">
            {/* Template Selection */}
            <div className="mb-1.5">
              <label className="mb-0.5 block text-[10px] text-gray-500">内置模板</label>
              <select
                value={selectedTemplate}
                onChange={(e) => handleTemplateSelect(e.target.value)}
                className="w-full rounded border border-gray-300 px-2 py-1 text-xs focus:border-blue-500 focus:outline-none"
              >
                <option value="">选择模板或使用自定义...</option>
                {templates.map((tpl) => (
                  <option key={tpl.path} value={tpl.path}>
                    {tpl.name} ({formatSize(tpl.size)}) - {tpl.description}
                  </option>
                ))}
              </select>
            </div>

            {/* Custom Shellcode */}
            <div className="flex gap-1">
              <input
                type="text"
                value={shellcodePath}
                onChange={(e) => {
                  setShellcodePath(e.target.value)
                  setSelectedTemplate('')
                }}
                className="flex-1 rounded border border-gray-300 px-2 py-1 text-xs focus:border-blue-500 focus:outline-none disabled:bg-gray-100"
                placeholder={selectedTemplate ? '使用内置模板' : '自定义 shellcode 文件...'}
                disabled={!!selectedTemplate}
              />
              <button
                onClick={handleSelectShellcode}
                disabled={!!selectedTemplate}
                className="flex items-center gap-1 rounded border border-gray-300 px-2 py-1 text-xs hover:bg-gray-50 disabled:opacity-50"
              >
                <FileUp className="h-3 w-3" />
                浏览
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Options Section */}
      <div className="rounded border border-gray-200 bg-white">
        <button
          onClick={() => toggleSection('options')}
          className="flex w-full items-center justify-between px-2 py-1.5 hover:bg-gray-50"
        >
          <span className="text-xs font-medium">注入选项</span>
          {expandedSections.options ? (
            <ChevronDown className="h-3 w-3 text-gray-400" />
          ) : (
            <ChevronRight className="h-3 w-3 text-gray-400" />
          )}
        </button>

        {expandedSections.options && (
          <div className="border-t border-gray-100 px-2 pb-2 pt-1.5">
            <div className="grid grid-cols-2 gap-1">
              {/* Method */}
              <div className="col-span-2">
                <label className="mb-0.5 block text-[10px] text-gray-500">注入方法</label>
                <select
                  value={method}
                  onChange={(e) => setMethod(e.target.value)}
                  className="w-full rounded border border-gray-300 px-2 py-1 text-xs focus:border-blue-500 focus:outline-none"
                >
                  <option value="function">Function Patching (代码洞)</option>
                  <option value="entrypoint">Entry Point Hijacking (入口点)</option>
                  <option value="tlsinject">TLS Injection (TLS回调)</option>
                  <option value="eat">EAT Patching (导出表, 仅DLL)</option>
                </select>
                <div className="mt-0.5 text-[10px] text-gray-400">
                  {method === 'function' && '在 .text 节中找到代码洞并放入 shellcode'}
                  {method === 'entrypoint' && '修改入口点直接执行 shellcode'}
                  {method === 'tlsinject' && '使用 TLS 回调在主入口点之前执行代码'}
                  {method === 'eat' && '修补导出函数地址指向 shellcode'}
                </div>
              </div>

              {/* EAT Function Name */}
              {method === 'eat' && (
                <div className="col-span-2">
                  <label className="mb-0.5 block text-[10px] text-gray-500">
                    函数名 (留空使用第一个导出)
                  </label>
                  <input
                    type="text"
                    value={funcName}
                    onChange={(e) => setFuncName(e.target.value)}
                    className="w-full rounded border border-gray-300 px-2 py-1 text-xs focus:border-blue-500 focus:outline-none"
                    placeholder="如: DllMain"
                  />
                </div>
              )}
            </div>

            {/* Checkboxes */}
            <div className="mt-1.5 space-y-1">
              <label className="flex items-center gap-1.5">
                <input
                  type="checkbox"
                  checked={backup}
                  onChange={(e) => setBackup(e.target.checked)}
                  className="h-3 w-3 rounded border-gray-300"
                />
                <span className="text-[11px]">创建备份 (.bak)</span>
              </label>
              <label className="flex items-center gap-1.5">
                <input
                  type="checkbox"
                  checked={preserveSig}
                  onChange={(e) => setPreserveSig(e.target.checked)}
                  className="h-3 w-3 rounded border-gray-300"
                />
                <span className="text-[11px]">保留数字签名 (将失效)</span>
              </label>
            </div>

            {/* Warning */}
            <div className="mt-1.5 flex items-start gap-1 rounded border border-amber-200 bg-amber-50 p-1.5">
              <AlertTriangle className="h-3 w-3 flex-shrink-0 text-amber-500" />
              <div className="text-[10px]">
                <span className="font-medium text-amber-700">仅限安全研究</span>
                <span className="text-amber-600"> - 未经授权使用属违法行为</span>
              </div>
            </div>

            {/* Inject Button */}
            <button
              onClick={handleInject}
              disabled={isInjecting || !pePath || !shellcodePath}
              className="mt-1.5 flex w-full items-center justify-center gap-1 rounded bg-blue-500 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-600 disabled:opacity-50"
            >
              {isInjecting ? (
                <>
                  <Loader2 className="h-3 w-3 animate-spin" />
                  注入中...
                </>
              ) : (
                <>
                  <Play className="h-3 w-3" />
                  注入 Shellcode
                </>
              )}
            </button>

            {/* Error */}
            {error && (
              <div className="mt-1.5 flex items-start gap-1 rounded border border-red-200 bg-red-50 p-1.5 text-[11px] text-red-600">
                <XCircle className="h-3 w-3 flex-shrink-0 mt-0.5" />
                <p>{error}</p>
              </div>
            )}

            {/* Result */}
            {result && (
              <div
                className={cn(
                  'mt-1.5 flex items-start gap-1 rounded border p-1.5 text-[11px]',
                  result.success
                    ? 'border-green-200 bg-green-50 text-green-700'
                    : 'border-red-200 bg-red-50 text-red-600'
                )}
              >
                {result.success ? (
                  <CheckCircle className="h-3.5 w-3.5 flex-shrink-0" />
                ) : (
                  <XCircle className="h-3.5 w-3.5 flex-shrink-0" />
                )}
                <div>
                  <p className="font-medium">{result.message}</p>
                  {result.success && (
                    <div className="mt-0.5 text-gray-600">
                      <p>输出: {result.outputPath}</p>
                      <p>大小: {formatSize(result.originalSize)} → {formatSize(result.modifiedSize)}</p>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

export default InjectPage
