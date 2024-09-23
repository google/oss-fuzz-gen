import click
import json

from .api import is_supported_proj, get_proj_headers

@click.group()
def cli():
    pass

@click.command(name='is_supported_proj')
@click.argument('proj')
def command_is_supported_proj(proj: str):
    """Command for is_supported_proj API"""
    result = is_supported_proj(proj)
    click.echo(f"{result}")

@click.command(name='get_proj_headers')
@click.argument('proj')
def command_get_proj_headers(proj: str):
    """Command for get_proj_headers API"""
    result = get_proj_headers(proj)
    click.echo(json.dumps(result, indent=2))

cli.add_command(command_is_supported_proj, name='supp')
cli.add_command(command_get_proj_headers, name='infer')

if __name__ == "__main__":
    cli()
