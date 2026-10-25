"""Validated API contracts for all eight tools."""
from typing import Literal
from pydantic import BaseModel, Field, field_validator
from config import settings

Language = Literal['auto', 'python', 'javascript', 'typescript', 'java', 'c', 'cpp', 'csharp', 'go', 'rust', 'sql', 'html', 'css']

class BaseAnalysis(BaseModel):
    language: Language = 'python'
    save_history: bool = False

class CodeRequest(BaseAnalysis):
    code: str = Field(min_length=1, max_length=settings.max_code_length)

    @field_validator('code')
    @classmethod
    def check_code(cls, value: str) -> str:
        if not value.strip():
            raise ValueError('Code must not be blank.')
        return value

class GenerateRequest(BaseAnalysis):
    prompt: str = Field(min_length=1, max_length=4000)

    @field_validator('prompt')
    @classmethod
    def check_prompt(cls, value: str) -> str:
        if not value.strip():
            raise ValueError('Prompt must not be blank.')
        return value

class CompareRequest(BaseAnalysis):
    code1: str = Field(min_length=1, max_length=settings.max_code_length)
    code2: str = Field(min_length=1, max_length=settings.max_code_length)

    @field_validator('code1', 'code2')
    @classmethod
    def check_snippet(cls, value: str) -> str:
        if not value.strip():
            raise ValueError('Both snippets are required.')
        return value

class AnalysisResponse(BaseModel):
    tool: str
    result: str
    engine: Literal['gemini', 'ruff', 'diff', 'bandit']
    cached: bool = False
    duration_ms: int = 0
    saved: bool = False
    disclaimer: str = ''

class HistoryEntry(BaseModel):
    id: int
    tool: str
    language: str
    code: str
    code2: str
    prompt: str
    result: str
    engine: str
    created_at: str
