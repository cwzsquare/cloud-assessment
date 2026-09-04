from __future__ import annotations

import argparse
import io
import html
import re
import zipfile
from pathlib import Path

from PIL import Image

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
WP_NS = "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"
PIC_NS = "http://schemas.openxmlformats.org/drawingml/2006/picture"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"

CLAUSES = (
    ("3.1.1.1", "数据格式分析", "3.1.1.1-data-format-analysis.webp"),
    ("3.1.1.2", "数据格式定义", "3.1.1.2-data-format-definition.webp"),
    ("3.1.1.3", "数据格式转换实现", "3.1.1.3-data-format-conversion.webp"),
    ("3.1.1.4", "数据标准化清洗", "3.1.1.4-data-cleaning.webp"),
    ("3.1.1.5", "数据质量评估", "3.1.1.5-data-quality.webp"),
    ("3.1.1.6", "数据格式优化", "3.1.1.6-data-format-optimization.webp"),
    ("3.1.2.1", "工具集成框架构建", "3.1.2.1-integration-framework.webp"),
    ("3.1.2.2", "云上API安全评估工具接入适配", "3.1.2.2-api-adapter.webp"),
    ("3.1.2.3", "云原生安全评估工具接入适配", "3.1.2.3-cloudnative-adapter.webp"),
    ("3.1.2.4", "智算云安全评估工具接入适配", "3.1.2.4-smartcloud-adapter.webp"),
    ("3.1.3.1", "调用参数标准化", "3.1.3.1-request-normalization.webp"),
    ("3.1.3.2", "调用流程协调", "3.1.3.2-flow-coordination.webp"),
    ("3.1.4.1", "输出格式归一化", "3.1.4.1-output-normalization.webp"),
    ("3.1.4.2", "结果汇总整合", "3.1.4.2-result-aggregation.webp"),
    ("3.2.1.1", "指标录入管理", "3.2.1.1-indicator-management.webp"),
    ("3.2.1.2", "评估指标赋权", "3.2.1.2-indicator-weighting.webp"),
    ("3.2.2", "结果分析判定", "3.2.2-result-analysis.webp"),
    ("3.2.3", "综合态势展示", "3.2.3-security-posture.webp"),
    ("3.2.4.1", "API工具结果详览", "3.2.4.1-api-detail.webp"),
    ("3.2.4.2", "云原生工具结果详览", "3.2.4.2-cloudnative-detail.webp"),
    ("3.2.4.3", "智算云工具结果详览", "3.2.4.3-smartcloud-detail.webp"),
    ("3.2.5.1", "数据筛选交互", "3.2.5.1-filter-interaction.webp"),
    ("3.2.5.2", "结果交互查询", "3.2.5.2-result-query.webp"),
)




def jpeg_bytes(path: Path, quality: int) -> tuple[bytes, int, int]:
    with Image.open(path) as image:
        image = image.convert("RGB")
        width, height = image.size
        max_width = 1550
        if width > max_width:
            height = round(height * max_width / width)
            image = image.resize((max_width, height), Image.Resampling.LANCZOS)
            width = max_width
        output = io.BytesIO()
        image.save(output, format="JPEG", quality=quality, optimize=True)
        return output.getvalue(), width, height




def image_xml(rel_id: str, image_number: int, width_emu: int, height_emu: int) -> bytes:
    return f"""<w:p xmlns:w="{W_NS}" xmlns:wp="{WP_NS}" xmlns:a="{A_NS}" xmlns:pic="{PIC_NS}" xmlns:r="{R_NS}">
<w:pPr><w:jc w:val="center"/><w:spacing w:before="120" w:after="0"/></w:pPr>
<w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="{width_emu}" cy="{height_emu}"/><wp:effectExtent l="0" t="0" r="0" b="0"/><wp:docPr id="{image_number}" name="Acceptance screenshot {image_number}"/><a:graphic><a:graphicData uri="{PIC_NS}"><pic:pic><pic:nvPicPr><pic:cNvPr id="0" name="screenshot-{image_number}.jpg"/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill><a:blip r:embed="{rel_id}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{width_emu}" cy="{height_emu}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r>
</w:p>""".encode("utf-8")


def caption_xml(code: str, name: str) -> bytes:
    return f"""<w:p><w:pPr><w:jc w:val="center"/><w:spacing w:before="60" w:after="120"/></w:pPr><w:r><w:rPr><w:i/></w:rPr><w:t>页面截图：{code} {name}</w:t></w:r></w:p>""".encode("utf-8")


def build_document_preserving_xml(source: Path, screenshot_dir: Path, output: Path, quality: int) -> None:
    with zipfile.ZipFile(source, "r") as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    document_xml = files["word/document.xml"]
    paragraph_pattern = re.compile(rb"<w:p(?:\s[^>]*)?>.*?</w:p>", re.DOTALL)
    paragraphs: list[tuple[int, int, str]] = []
    for match in paragraph_pattern.finditer(document_xml):
        text_values = re.findall(rb"<w:t(?:\s[^>]*)?>(.*?)</w:t>", match.group(0), re.DOTALL)
        paragraph_text_value = html.unescape(b"".join(text_values).decode("utf-8"))
        paragraphs.append((match.start(), match.end(), paragraph_text_value))
    anchor_positions: dict[str, tuple[int, int]] = {}
    for code, _, _ in CLAUSES:
        matches = [item for item in paragraphs if item[2].startswith(code)]
        if not matches:
            raise ValueError(f"clause anchor not found: {code}")
        anchor_positions[code] = matches[0][:2]
    last_anchor_end = anchor_positions[CLAUSES[-1][0]][1]
    next_three_three = next((item for item in paragraphs if item[0] > last_anchor_end and item[2].startswith("3.3")), None)
    boundary_positions: list[tuple[int, str, str, bytes, bytes, str]] = []
    relationship_xml = files["word/_rels/document.xml.rels"]
    relationship_numbers = [int(value) for value in re.findall(rb'Id="rId(\d+)"', relationship_xml)]
    next_rel_number = max(relationship_numbers, default=0) + 1
    width_emu = round(6.1 * 914400)
    media_number = len([name for name in files if name.startswith("word/media/")]) + 1
    for index, (code, name, filename) in enumerate(CLAUSES):
        if index + 1 < len(CLAUSES):
            boundary = anchor_positions[CLAUSES[index + 1][0]][0]
        elif next_three_three:
            boundary = next_three_three[0]
        else:
            boundary = document_xml.rfind(b"</w:body>")
        source_image = screenshot_dir / filename
        if not source_image.is_file():
            raise FileNotFoundError(source_image)
        image_data, pixel_width, pixel_height = jpeg_bytes(source_image, quality)
        height_emu = round(width_emu * pixel_height / pixel_width)
        rel_id = f"rId{next_rel_number}"
        media_name = f"screenshot-{media_number}.jpg"
        relationship = f'<Relationship Id="{rel_id}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/{media_name}"/>'.encode("ascii")
        boundary_positions.append((boundary, code, name, image_xml(rel_id, index + 1, width_emu, height_emu), caption_xml(code, name), media_name))
        relationship_xml = relationship_xml.replace(b"</Relationships>", relationship + b"</Relationships>", 1)
        files[f"word/media/{media_name}"] = image_data
        next_rel_number += 1
        media_number += 1
    for boundary, _, _, image_node, caption_node, _ in reversed(boundary_positions):
        document_xml = document_xml[:boundary] + image_node + caption_node + document_xml[boundary:]
    content_types = files["[Content_Types].xml"]
    if not re.search(rb'<Default Extension="jpg" ', content_types):
        content_types = content_types.replace(b"</Types>", b'<Default Extension="jpg" ContentType="image/jpeg"/></Types>', 1)
    files["word/document.xml"] = document_xml
    files["word/_rels/document.xml.rels"] = relationship_xml
    files["[Content_Types].xml"] = content_types
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    


def main() -> int:
    parser = argparse.ArgumentParser(description="Insert acceptance screenshots after their matching DOCX clauses.")
    parser.add_argument("source", type=Path)
    parser.add_argument("screenshot_dir", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--quality", type=int, default=90)
    args = parser.parse_args()
    if not 1 <= args.quality <= 100:
        parser.error("--quality must be between 1 and 100")
    build_document_preserving_xml(args.source, args.screenshot_dir, args.output, args.quality)
    print(f"wrote {args.output} ({len(CLAUSES)} screenshots)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
