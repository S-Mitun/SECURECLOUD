import React, { useState, useEffect, useRef } from 'react';
import { 
  ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, 
  ZoomIn, ZoomOut, Maximize2, Minimize2, Grid, List, 
  FileText, Columns, Layout, Printer, MessageSquare, Check
} from 'lucide-react';

export function PresentationViewer({ presentationData, data, filename, isFullscreen = false, downloadUrl }) {
  const pData = presentationData || data || {};
  const [currentSlideIndex, setCurrentSlideIndex] = useState(0);
  const [zoom, setZoom] = useState(100);
  const [viewMode, setViewMode] = useState('projector'); // 'projector' | 'flow' | 'outline'
  const [showThumbnails, setShowThumbnails] = useState(true);
  const [showNotes, setShowNotes] = useState(false);
  const containerRef = useRef(null);

  const slides = pData?.slides || [];
  const totalSlides = slides.length;
  const currentSlide = slides[currentSlideIndex];
  const aspectRatio = pData?.aspect_ratio || 1.778;

  // Keyboard navigation for presentation mode
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (viewMode !== 'projector') return;
      if (['ArrowRight', 'ArrowDown', 'Space', 'PageDown'].includes(e.code)) {
        e.preventDefault();
        setCurrentSlideIndex((prev) => Math.min(totalSlides - 1, prev + 1));
      } else if (['ArrowLeft', 'ArrowUp', 'PageUp'].includes(e.code)) {
        e.preventDefault();
        setCurrentSlideIndex((prev) => Math.max(0, prev - 1));
      } else if (e.code === 'Home') {
        e.preventDefault();
        setCurrentSlideIndex(0);
      } else if (e.code === 'End') {
        e.preventDefault();
        setCurrentSlideIndex(totalSlides - 1);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [totalSlides, viewMode]);

  if (!pData || totalSlides === 0) {
    return (
      <div className="w-full h-96 flex flex-col items-center justify-center text-slate-400 font-mono text-xs bg-slate-950 rounded-xl border border-slate-800">
        <FileText className="w-12 h-12 text-slate-600 mb-2" />
        <div>No presentation slides available for rendering.</div>
      </div>
    );
  }

  const renderSlideCanvas = (slide, index, isSingle = true) => {
    const slideBg = slide.background_color || '#ffffff';
    const isDarkBg = slideBg.toLowerCase() !== '#ffffff' && slideBg.toLowerCase() !== '#fff' && !slideBg.toLowerCase().startsWith('#f');

    return (
      <div
        key={index}
        className="relative rounded-lg overflow-hidden shadow-2xl border border-slate-300 transition-all duration-150 my-auto select-text"
        style={{
          width: isSingle ? `${Math.min(1000, 920 * (zoom / 100))}px` : '100%',
          maxWidth: isSingle ? '100%' : '900px',
          aspectRatio: `${aspectRatio}`,
          backgroundColor: slideBg,
          color: isDarkBg ? '#ffffff' : '#0f172a'
        }}
      >
        {/* Render Each Positioned Element */}
        {slide.elements && slide.elements.map((el, eIdx) => {
          const style = {
            position: 'absolute',
            left: `${el.left}%`,
            top: `${el.top}%`,
            width: `${el.width}%`,
            height: `${el.height}%`,
            backgroundColor: el.fill_color !== 'transparent' ? el.fill_color : undefined,
            borderColor: el.border_color !== 'transparent' ? el.border_color : undefined,
            borderWidth: el.border_color !== 'transparent' ? '1px' : '0',
            boxSizing: 'border-box'
          };

          // 1. Text Box with Preserved Multi-Level Paragraphs & Runs
          if (el.type === 'TEXT_BOX') {
            return (
              <div
                key={eIdx}
                style={style}
                className="overflow-hidden p-1 sm:p-2 flex flex-col justify-start leading-snug select-text"
              >
                {el.paragraphs && el.paragraphs.map((p, pIdx) => {
                  const levelIndent = (p.level || 0) * 16;
                  const isBullet = (p.level || 0) > 0;

                  return (
                    <div
                      key={pIdx}
                      style={{ 
                        textAlign: p.alignment || 'left',
                        paddingLeft: `${levelIndent}px`
                      }}
                      className="my-0.5 flex items-start gap-1.5"
                    >
                      {isBullet && (
                        <span className="text-slate-700 text-xs font-bold shrink-0 mt-0.5 select-none">
                          •
                        </span>
                      )}
                      <div className="flex-1">
                        {p.runs && p.runs.length > 0 ? (
                          p.runs.map((r, rIdx) => {
                            let textColor = r.color;
                            if (!textColor || textColor === '#ffffff') {
                              textColor = isDarkBg ? '#ffffff' : '#0f172a';
                            }

                            return (
                              <span
                                key={rIdx}
                                style={{
                                  color: textColor,
                                  fontWeight: r.bold ? '700' : '400',
                                  fontStyle: r.italic ? 'italic' : 'normal',
                                  fontSize: `${Math.max(11, (r.size_pt || 14) * (zoom / 100))}px`,
                                  fontFamily: r.font_name ? `"${r.font_name}", Inter, sans-serif` : 'Inter, sans-serif'
                                }}
                              >
                                {r.text}
                              </span>
                            );
                          })
                        ) : (
                          <span style={{ color: isDarkBg ? '#ffffff' : '#0f172a', fontSize: `${14 * (zoom / 100)}px` }}>
                            {p.text}
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            );
          }

          // 2. Embedded Graphic Image
          if (el.type === 'IMAGE' && el.data_url) {
            return (
              <div key={eIdx} style={style} className="overflow-hidden">
                <img
                  src={el.data_url}
                  alt="Slide graphic"
                  className="w-full h-full object-contain pointer-events-none"
                />
              </div>
            );
          }

          // 3. Formatted Table (PDF Document Styling)
          if (el.type === 'TABLE' && el.rows) {
            return (
              <div key={eIdx} style={style} className="overflow-auto border border-slate-300 rounded shadow-sm bg-white">
                <table className="w-full h-full text-xs text-left border-collapse">
                  <tbody>
                    {el.rows.map((row, rIdx) => (
                      <tr
                        key={rIdx}
                        className={rIdx === 0 ? 'bg-slate-100 font-bold border-b border-slate-300' : 'border-b border-slate-200 hover:bg-slate-50'}
                      >
                        {row.map((cell, cIdx) => (
                          <td
                            key={cIdx}
                            className="p-2 border-r border-slate-200 text-slate-900 text-xs font-mono"
                          >
                            {cell}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            );
          }

          // 4. Standard Graphic Shape
          if (el.type === 'SHAPE') {
            return <div key={eIdx} style={style} className="rounded-lg shadow-sm" />;
          }

          return null;
        })}
      </div>
    );
  };

  return (
    <div 
      ref={containerRef}
      className={`w-full flex flex-col bg-slate-950 text-slate-100 rounded-xl border border-slate-800 overflow-hidden shadow-2xl ${
        isFullscreen ? 'h-full' : 'h-[85vh]'
      }`}
    >
      {/* Top Controls Toolbar */}
      <div className="p-3 bg-slate-900 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 shrink-0">
        {/* Left: Presentation Info & View Mode Toggle */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
            <button
              onClick={() => setViewMode('projector')}
              className={`px-2.5 py-1 rounded text-xs font-semibold flex items-center gap-1.5 transition ${
                viewMode === 'projector' ? 'bg-orange-600 text-white shadow' : 'text-slate-400 hover:text-white'
              }`}
              title="Interactive Slide Projector View"
            >
              <Layout className="w-3.5 h-3.5" /> Projector
            </button>
            <button
              onClick={() => setViewMode('flow')}
              className={`px-2.5 py-1 rounded text-xs font-semibold flex items-center gap-1.5 transition ${
                viewMode === 'flow' ? 'bg-sky-600 text-white shadow' : 'text-slate-400 hover:text-white'
              }`}
              title="Continuous PDF Multi-Page Vertical Scroll"
            >
              <Columns className="w-3.5 h-3.5" /> Continuous PDF Flow
            </button>
            <button
              onClick={() => setViewMode('outline')}
              className={`px-2.5 py-1 rounded text-xs font-semibold flex items-center gap-1.5 transition ${
                viewMode === 'outline' ? 'bg-emerald-600 text-white shadow' : 'text-slate-400 hover:text-white'
              }`}
              title="Structured Text Outline & Reading View"
            >
              <List className="w-3.5 h-3.5" /> Outline
            </button>
          </div>

          {viewMode === 'projector' && (
            <button
              onClick={() => setShowThumbnails(!showThumbnails)}
              className={`p-1.5 rounded-lg border text-xs transition ${
                showThumbnails ? 'bg-slate-800 border-slate-700 text-white' : 'bg-slate-950 border-slate-800 text-slate-400'
              }`}
              title="Toggle Thumbnails Sidebar"
            >
              <Grid className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* Center: Slide Count / Title */}
        <div className="text-xs font-mono font-bold text-white flex items-center gap-2">
          <span className="px-2 py-0.5 bg-orange-950/80 border border-orange-500/40 text-orange-300 rounded font-bold">
            PPTX
          </span>
          <span className="truncate max-w-[200px] sm:max-w-xs">{filename}</span>
          <span className="text-slate-500">•</span>
          <span className="text-slate-400">{totalSlides} Slides</span>
        </div>

        {/* Right: Zoom & Notes Controls */}
        <div className="flex items-center gap-1.5">
          {viewMode !== 'outline' && (
            <div className="flex items-center gap-1 bg-slate-950 px-2 py-1 rounded-lg border border-slate-800 text-xs font-mono">
              <button
                onClick={() => setZoom(Math.max(50, zoom - 15))}
                className="text-slate-400 hover:text-white p-0.5"
                title="Zoom Out"
              >
                <ZoomOut className="w-3.5 h-3.5" />
              </button>
              <span className="px-1 text-slate-300 min-w-[40px] text-center">{zoom}%</span>
              <button
                onClick={() => setZoom(Math.min(180, zoom + 15))}
                className="text-slate-400 hover:text-white p-0.5"
                title="Zoom In"
              >
                <ZoomIn className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => setZoom(100)}
                className="text-[10px] text-orange-400 hover:text-orange-300 ml-1 border-l border-slate-800 pl-1.5 font-bold"
                title="Reset Zoom"
              >
                Reset
              </button>
            </div>
          )}

          {currentSlide?.notes && viewMode === 'projector' && (
            <button
              onClick={() => setShowNotes(!showNotes)}
              className={`p-1.5 rounded-lg border text-xs flex items-center gap-1 transition ${
                showNotes ? 'bg-amber-950 border-amber-500/50 text-amber-300' : 'bg-slate-900 border-slate-800 text-slate-400'
              }`}
              title="Toggle Speaker Notes"
            >
              <MessageSquare className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {/* Main Presentation Viewport */}
      <div className="flex-1 flex overflow-hidden relative">
        {/* 1. PROJECTOR MODE */}
        {viewMode === 'projector' && (
          <>
            {/* Left Slide Thumbnails Sidebar */}
            {showThumbnails && (
              <div className="w-48 sm:w-56 bg-slate-900/90 border-r border-slate-800 overflow-y-auto p-3 space-y-3 shrink-0 select-none">
                <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-2 font-bold">
                  Slides Overview ({totalSlides})
                </div>
                {slides.map((s, sIdx) => (
                  <div
                    key={sIdx}
                    onClick={() => setCurrentSlideIndex(sIdx)}
                    className={`cursor-pointer rounded-lg p-2 transition-all border ${
                      currentSlideIndex === sIdx
                        ? 'bg-orange-950/40 border-orange-500 shadow-md scale-[1.02]'
                        : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 mb-1">
                      <span className="font-bold">Slide {sIdx + 1}</span>
                      {s.notes && <span className="text-amber-400">📝</span>}
                    </div>
                    {/* Thumbnail Preview Box */}
                    <div 
                      className="w-full bg-white rounded border border-slate-300 overflow-hidden shadow-sm flex items-center justify-center p-1"
                      style={{ aspectRatio: `${aspectRatio}` }}
                    >
                      <span className="text-[9px] text-slate-900 font-bold text-center truncate">
                        {s.title || `Slide ${sIdx + 1}`}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Slide Stage Canvas */}
            <div className="flex-1 overflow-auto p-4 sm:p-8 flex flex-col items-center justify-center bg-slate-950 relative">
              {renderSlideCanvas(currentSlide, currentSlideIndex, true)}

              {/* Slide Notes Drawer Overlay */}
              {showNotes && currentSlide?.notes && (
                <div className="absolute bottom-4 left-4 right-4 bg-slate-900/95 border border-amber-500/40 rounded-xl p-4 shadow-2xl backdrop-blur max-h-48 overflow-y-auto">
                  <div className="text-xs font-bold text-amber-300 mb-1 flex items-center gap-1.5 font-mono">
                    <MessageSquare className="w-3.5 h-3.5" /> Slide {currentSlideIndex + 1} Speaker Notes
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed font-sans">{currentSlide.notes}</p>
                </div>
              )}
            </div>
          </>
        )}

        {/* 2. CONTINUOUS PDF FLOW MODE */}
        {viewMode === 'flow' && (
          <div className="flex-1 overflow-y-auto p-4 sm:p-8 flex flex-col items-center gap-8 bg-slate-950">
            <div className="text-xs font-mono text-slate-400 bg-slate-900 px-4 py-1.5 rounded-full border border-slate-800 flex items-center gap-2">
              <span className="text-sky-400 font-bold">Continuous Flow Mode:</span> All {totalSlides} slides rendered in multi-page document layout
            </div>

            {slides.map((s, idx) => (
              <div key={idx} className="w-full max-w-4xl flex flex-col items-center space-y-2">
                <div className="w-full flex items-center justify-between text-xs font-mono text-slate-400 px-1">
                  <span className="font-bold text-slate-300">Page / Slide {idx + 1} of {totalSlides}: {s.title}</span>
                  <span className="text-[10px] text-slate-500">SecureCloud Slide Engine</span>
                </div>
                {renderSlideCanvas(s, idx, false)}
                {s.notes && (
                  <div className="w-full bg-slate-900/80 border border-slate-800 rounded-lg p-3 text-xs text-slate-400 font-mono">
                    <strong className="text-amber-400">Notes:</strong> {s.notes}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* 3. STRUCTURED OUTLINE & READING VIEW */}
        {viewMode === 'outline' && (
          <div className="flex-1 overflow-y-auto p-4 sm:p-12 flex justify-center bg-slate-900/60">
            <div className="max-w-4xl w-full bg-white text-slate-950 p-8 sm:p-14 rounded-xl shadow-2xl min-h-full space-y-8" style={{ color: '#0f172a', backgroundColor: '#ffffff' }}>
              <div className="border-b-2 border-slate-200 pb-4 flex items-center justify-between">
                <div>
                  <h1 className="text-2xl font-black text-slate-900 tracking-tight">{filename}</h1>
                  <p className="text-xs text-slate-500 font-mono mt-1">Presentation Document Outline • {totalSlides} Slides</p>
                </div>
                <span className="px-3 py-1 bg-orange-100 text-orange-800 font-mono text-xs font-bold rounded-lg border border-orange-200">
                  SLIDE DECK OUTLINE
                </span>
              </div>

              {slides.map((s, idx) => (
                <div key={idx} className="border-b border-slate-200 pb-6 space-y-3">
                  <div className="flex items-center gap-3">
                    <span className="w-7 h-7 rounded-lg bg-orange-600 text-white font-mono font-bold text-xs flex items-center justify-center shrink-0">
                      {idx + 1}
                    </span>
                    <h2 className="text-lg font-bold text-slate-900">{s.title || `Slide ${idx + 1}`}</h2>
                  </div>

                  {s.outline && s.outline.length > 0 ? (
                    <div className="pl-10 space-y-2">
                      {s.outline.map((item, iIdx) => {
                        if (item.is_table && item.table_rows) {
                          return (
                            <div key={iIdx} className="my-3 overflow-x-auto border border-slate-300 rounded shadow-sm">
                              <table className="w-full text-xs text-left border-collapse font-mono">
                                <tbody>
                                  {item.table_rows.map((row, rIdx) => (
                                    <tr key={rIdx} className={rIdx === 0 ? 'bg-slate-100 font-bold border-b border-slate-300' : 'border-b border-slate-200'}>
                                      {row.map((c, cIdx) => (
                                        <td key={cIdx} className="p-2 border-r border-slate-200 text-slate-800">
                                          {c}
                                        </td>
                                      ))}
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          );
                        }

                        return (
                          <div key={iIdx} className="flex items-start gap-2 text-sm text-slate-800 leading-relaxed" style={{ paddingLeft: `${item.level * 16}px` }}>
                            <span className="text-orange-500 font-bold mt-1 select-none">•</span>
                            <span>{item.text}</span>
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <p className="pl-10 text-xs text-slate-400 italic">Graphic / visual slide layout.</p>
                  )}

                  {s.notes && (
                    <div className="ml-10 bg-amber-50 border border-amber-200 rounded-lg p-3 text-xs text-amber-900 leading-relaxed">
                      <strong>Speaker Notes:</strong> {s.notes}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Bottom Navigation Toolbar (Projector Mode Only) */}
      {viewMode === 'projector' && (
        <div className="p-3 bg-slate-900 border-t border-slate-800 flex items-center justify-between gap-4 shrink-0">
          {/* Previous Controls */}
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setCurrentSlideIndex(0)}
              disabled={currentSlideIndex === 0}
              className="p-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-300 rounded-lg transition"
              title="First Slide (Home)"
            >
              <ChevronsLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => setCurrentSlideIndex(Math.max(0, currentSlideIndex - 1))}
              disabled={currentSlideIndex === 0}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 rounded-lg text-xs font-bold flex items-center gap-1 transition"
              title="Previous Slide (Left Arrow)"
            >
              <ChevronLeft className="w-4 h-4" />
              <span className="hidden sm:inline">Previous</span>
            </button>
          </div>

          {/* Current Slide Indicator */}
          <div className="text-xs font-mono font-bold text-white bg-slate-950 px-4 py-1.5 rounded-full border border-slate-800 shadow-inner flex items-center gap-2">
            <span className="text-orange-400">Slide</span>
            <span className="text-base">{currentSlideIndex + 1}</span>
            <span className="text-slate-500">/</span>
            <span className="text-slate-400">{totalSlides}</span>
          </div>

          {/* Next Controls */}
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setCurrentSlideIndex(Math.min(totalSlides - 1, currentSlideIndex + 1))}
              disabled={currentSlideIndex >= totalSlides - 1}
              className="px-3 py-1.5 bg-orange-600 hover:bg-orange-500 disabled:opacity-40 text-white rounded-lg text-xs font-bold flex items-center gap-1 transition shadow"
              title="Next Slide (Right Arrow / Space)"
            >
              <span className="hidden sm:inline">Next</span>
              <ChevronRight className="w-4 h-4" />
            </button>
            <button
              onClick={() => setCurrentSlideIndex(totalSlides - 1)}
              disabled={currentSlideIndex >= totalSlides - 1}
              className="p-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-300 rounded-lg transition"
              title="Last Slide (End)"
            >
              <ChevronsRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
