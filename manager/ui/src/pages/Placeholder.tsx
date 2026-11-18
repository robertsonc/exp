import type { JSX } from 'preact';
import { EmptyState } from '../components/atoms';
import { Link } from '../components/viz';
import { PageHeader } from './common';

export function NotFound(): JSX.Element {
  return (
    <>
      <PageHeader title="Page not found" />
      <EmptyState title="There is nothing at this address" action={<Link to="/fleet" class="btn">Go to the fleet overview</Link>}>Check the link, or use search to find a host, site or component.</EmptyState>
    </>
  );
}
