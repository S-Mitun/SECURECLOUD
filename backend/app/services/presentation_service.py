import io
import os
import base64
import hashlib
from typing import Dict, Any, List, Optional
import pptx
from pptx.util import Inches, Pt
from pptx.enum.shapes import MSO_SHAPE_TYPE

class PresentationService:
    CACHE_DIR = os.path.join("storage", "cache", "presentations")

    @classmethod
    def _ensure_cache_dir(cls):
        os.makedirs(cls.CACHE_DIR, exist_ok=True)

    @classmethod
    def _parse_shape_recursive(cls, shape, slide_width_pt: float, slide_height_pt: float, base_left: float = 0, base_top: float = 0) -> List[Dict[str, Any]]:
        elements = []
        try:
            # Handle Group Shapes recursively
            if shape.shape_type == MSO_SHAPE_TYPE.GROUP:
                for sub_shape in shape.shapes:
                    elements.extend(cls._parse_shape_recursive(sub_shape, slide_width_pt, slide_height_pt, base_left, base_top))
                return elements

            # Calculate percentage-based bounding box relative to slide canvas
            left_pct = round(((shape.left.pt + base_left) / slide_width_pt) * 100, 2) if slide_width_pt else 0
            top_pct = round(((shape.top.pt + base_top) / slide_height_pt) * 100, 2) if slide_height_pt else 0
            width_pct = round((shape.width.pt / slide_width_pt) * 100, 2) if slide_width_pt else 100
            height_pct = round((shape.height.pt / slide_height_pt) * 100, 2) if slide_height_pt else 20

            # 1. Text Frame / Shape with Text
            if shape.has_text_frame:
                paragraphs_data = []
                for p in shape.text_frame.paragraphs:
                    runs_data = []
                    for r in p.runs:
                        font_color = "#0f172a"  # Crisp high-contrast dark text
                        try:
                            if r.font and r.font.color and r.font.color.rgb:
                                font_color = f"#{r.font.color.rgb}"
                        except Exception:
                            pass

                        runs_data.append({
                            "text": r.text,
                            "bold": bool(r.font.bold) if r.font else False,
                            "italic": bool(r.font.italic) if r.font else False,
                            "size_pt": r.font.size.pt if r.font and r.font.size else 14,
                            "font_name": r.font.name if r.font and r.font.name else "Inter",
                            "color": font_color
                        })

                    if p.text.strip():
                        align_str = "left"
                        try:
                            if p.alignment:
                                align_map = {1: "left", 2: "center", 3: "right", 4: "justify"}
                                align_str = align_map.get(int(p.alignment), "left")
                        except Exception:
                            pass

                        paragraphs_data.append({
                            "text": p.text,
                            "alignment": align_str,
                            "level": p.level or 0,
                            "runs": runs_data
                        })

                if paragraphs_data:
                    fill_color = "transparent"
                    border_color = "transparent"
                    try:
                        if shape.fill and shape.fill.type == 1 and hasattr(shape.fill, "fore_color") and shape.fill.fore_color.rgb:
                            fill_color = f"#{shape.fill.fore_color.rgb}"
                        if shape.line and shape.line.color and shape.line.color.rgb:
                            border_color = f"#{shape.line.color.rgb}"
                    except Exception:
                        pass

                    elements.append({
                        "type": "TEXT_BOX",
                        "left": left_pct,
                        "top": top_pct,
                        "width": width_pct,
                        "height": height_pct,
                        "fill_color": fill_color,
                        "border_color": border_color,
                        "paragraphs": paragraphs_data
                    })

            # 2. Picture / Embedded Graphic
            elif shape.shape_type == MSO_SHAPE_TYPE.PICTURE:
                try:
                    image_bytes = shape.image.blob
                    content_type = shape.image.content_type
                    b64_img = base64.b64encode(image_bytes).decode("utf-8")
                    data_url = f"data:{content_type};base64,{b64_img}"

                    elements.append({
                        "type": "IMAGE",
                        "left": left_pct,
                        "top": top_pct,
                        "width": width_pct,
                        "height": height_pct,
                        "data_url": data_url
                    })
                except Exception:
                    pass

            # 3. Tables
            elif shape.has_table:
                tbl = shape.table
                rows_data = []
                for r in tbl.rows:
                    row_cells = []
                    for c in r.cells:
                        row_cells.append(c.text.strip())
                    rows_data.append(row_cells)

                elements.append({
                    "type": "TABLE",
                    "left": left_pct,
                    "top": top_pct,
                    "width": width_pct,
                    "height": height_pct,
                    "rows": rows_data
                })

            # 4. Standard Geometry Auto Shape
            elif shape.shape_type == MSO_SHAPE_TYPE.AUTO_SHAPE:
                fill_color = "#f8fafc"
                border_color = "#cbd5e1"
                try:
                    if shape.fill and shape.fill.type == 1 and hasattr(shape.fill, "fore_color") and shape.fill.fore_color.rgb:
                        fill_color = f"#{shape.fill.fore_color.rgb}"
                    if shape.line and shape.line.color and shape.line.color.rgb:
                        border_color = f"#{shape.line.color.rgb}"
                except Exception:
                    pass

                elements.append({
                    "type": "SHAPE",
                    "left": left_pct,
                    "top": top_pct,
                    "width": width_pct,
                    "height": height_pct,
                    "fill_color": fill_color,
                    "border_color": border_color
                })

        except Exception as ex:
            print(f"[PresentationService] Shape parsing notice: {ex}")

        return elements

    @classmethod
    def render_presentation(cls, file_bytes: bytes, file_hash: str, filename: str) -> Dict[str, Any]:
        """
        Parses PPTX file into a high-fidelity visual slide deck representation
        preserving slide width, height, aspect ratio, shapes, images, tables,
        notes, outlines, fonts, colors, and coordinates.
        """
        cls._ensure_cache_dir()

        try:
            prs = pptx.Presentation(io.BytesIO(file_bytes))
        except Exception as e:
            return {
                "format": "PRESENTATION_ERROR",
                "filename": filename,
                "error": f"Failed to parse presentation: {str(e)}"
            }

        slide_width_pt = prs.slide_width.pt if hasattr(prs, "slide_width") else 720.0
        slide_height_pt = prs.slide_height.pt if hasattr(prs, "slide_height") else 540.0
        aspect_ratio = round(slide_width_pt / slide_height_pt, 3) if slide_height_pt > 0 else 1.778

        slides_data: List[Dict[str, Any]] = []

        for idx, slide in enumerate(prs.slides, 1):
            slide_elements: List[Dict[str, Any]] = []
            slide_title = ""
            bg_color = "#ffffff"  # Clean crisp white background matching PDF layout

            # Check background fill
            try:
                if slide.background and slide.background.fill:
                    fill = slide.background.fill
                    if fill.type == 1 and hasattr(fill, "fore_color") and fill.fore_color.rgb:
                        bg_color = f"#{fill.fore_color.rgb}"
            except Exception:
                pass

            # Parse shapes recursively
            for shape in slide.shapes:
                # Detect slide title from placeholders
                if not slide_title and shape.shape_type == MSO_SHAPE_TYPE.PLACEHOLDER and shape.has_text_frame:
                    t_text = shape.text_frame.text.strip()
                    if t_text:
                        slide_title = t_text.splitlines()[0]

                elements = cls._parse_shape_recursive(shape, slide_width_pt, slide_height_pt)
                slide_elements.extend(elements)

            # Slide notes extraction
            notes_text = ""
            try:
                if slide.has_notes_slide and slide.notes_slide.notes_text_frame:
                    notes_text = slide.notes_slide.notes_text_frame.text.strip()
            except Exception:
                pass

            # Structured text outline of the slide
            outline_items = []
            for el in slide_elements:
                if el["type"] == "TEXT_BOX":
                    for p in el.get("paragraphs", []):
                        if p["text"].strip():
                            outline_items.append({
                                "text": p["text"].strip(),
                                "level": p.get("level", 0),
                                "align": p.get("alignment", "left")
                            })
                elif el["type"] == "TABLE":
                    outline_items.append({
                        "text": f"[Table: {len(el.get('rows', []))} rows]",
                        "level": 1,
                        "align": "left",
                        "is_table": True,
                        "table_rows": el.get("rows", [])
                    })

            slides_data.append({
                "slide_number": idx,
                "title": slide_title or f"Slide {idx}",
                "background_color": bg_color,
                "notes": notes_text,
                "elements": slide_elements,
                "outline": outline_items
            })

        return {
            "format": "PRESENTATION_RENDERED",
            "filename": filename,
            "file_hash": file_hash,
            "slide_count": len(slides_data),
            "slide_width_pt": slide_width_pt,
            "slide_height_pt": slide_height_pt,
            "aspect_ratio": aspect_ratio,
            "aspect_ratio_label": "16:9" if aspect_ratio >= 1.7 else "4:3",
            "slides": slides_data
        }
