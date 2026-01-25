
import sys
import os
import asyncio
import logging
from rich.console import Console
from rich.table import Table

# Add src to path
sys.path.append(os.path.join(os.getcwd(), "src"))

from mcp_sentinel.rag.vector_store import VectorStore
from mcp_sentinel.rag.knowledge_base import KnowledgeBase

logging.basicConfig(level=logging.INFO)
console = Console()

async def populate():
    console.print("[bold blue]Starting Knowledge Base Population (Parallel Mode)...[/bold blue]")
    
    # Initialize VectorStore and KnowledgeBase
    persist_dir = os.path.join(os.getcwd(), "data", "chroma_db")
    store = VectorStore(persist_dir=persist_dir)
    kb = KnowledgeBase(store)
    
    try:
        # Run population asynchronously
        stats = await kb.populate_defaults_async()
        
        # Display results
        table = Table(title="Knowledge Base Population Stats")
        table.add_column("Collection", style="cyan")
        table.add_column("Count", style="green")
        
        for collection, count in stats.items():
            table.add_row(collection, str(count))
            
        console.print(table)
        console.print(f"[bold green]Population complete! Total items: {stats.get('total', 0)}[/bold green]")
        
    except Exception as e:
        console.print(f"[bold red]Error during population: {e}[/bold red]")
        raise

def main():
    asyncio.run(populate())

if __name__ == "__main__":
    main()
