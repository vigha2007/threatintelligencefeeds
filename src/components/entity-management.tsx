import { useState } from "react";
import { useSuspenseQuery, useMutation, useQueryClient, queryOptions } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { motion } from "framer-motion";
import { Plus, Trash2, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter,
} from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { listEntity, createEntity, deleteEntity } from "@/lib/entities.functions";
import { entities, type EntityKey, severityEnum } from "@/lib/threat-entities";

const sevColors: Record<string, string> = {
  critical: "#FF4D4D", high: "#FFB020", medium: "#7B61FF", low: "#00FFA3",
};

const listQuery = (entity: EntityKey) =>
  queryOptions({
    queryKey: ["entity", entity],
    queryFn: () => listEntity({ data: { entity } }),
    staleTime: 15_000,
  });

export function EntityManagementPage({ entity }: { entity: EntityKey }) {
  const def = entities[entity];
  const qc = useQueryClient();
  const list = useServerFn(listEntity);
  const create = useServerFn(createEntity);
  const del = useServerFn(deleteEntity);
  const { data } = useSuspenseQuery({ ...listQuery(entity), queryFn: () => list({ data: { entity } }) });

  const [open, setOpen] = useState(false);

  const createMutation = useMutation({
    mutationFn: (values: Record<string, unknown>) => create({ data: { entity, values } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["entity", entity] });
      qc.invalidateQueries({ queryKey: ["dashboard-metrics"] });
      toast.success(`${def.singular} added`);
      setOpen(false);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => del({ data: { entity, id } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["entity", entity] });
      qc.invalidateQueries({ queryKey: ["dashboard-metrics"] });
      toast.success("Deleted");
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">{def.label}</h1>
          <p className="text-sm text-muted-foreground">Manage your {def.label.toLowerCase()} records. All dashboard metrics are computed from this data.</p>
        </div>
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogTrigger asChild>
            <Button><Plus className="mr-1 h-4 w-4" /> Add {def.singular}</Button>
          </DialogTrigger>
          <DialogContent className="max-w-lg">
            <DialogHeader><DialogTitle>Add {def.singular}</DialogTitle></DialogHeader>
            <CreateForm entity={entity} loading={createMutation.isPending} onSubmit={(v) => createMutation.mutate(v)} />
          </DialogContent>
        </Dialog>
      </motion.div>

      <div className="glass rounded-2xl p-4">
        {data.rows.length === 0 ? (
          <div className="p-8 text-center text-sm text-muted-foreground">No records yet. Click "Add {def.singular}" to create one.</div>
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  {def.fields.slice(0, 4).map((f) => <TableHead key={f.name}>{f.label}</TableHead>)}
                  <TableHead>Severity</TableHead>
                  <TableHead>Date</TableHead>
                  <TableHead className="w-12"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.rows.map((row) => {
                  const sev = String(row.severity ?? "");
                  return (
                    <TableRow key={String(row.id)}>
                      {def.fields.slice(0, 4).map((f) => (
                        <TableCell key={f.name} className="max-w-[260px] truncate text-white/90">
                          {f.name === "severity" ? null : String(row[f.name] ?? "—")}
                        </TableCell>
                      ))}
                      <TableCell>
                        <span className="rounded-full px-2 py-0.5 text-[10px] font-bold uppercase" style={{ background: `${sevColors[sev]}1f`, color: sevColors[sev] }}>
                          {sev}
                        </span>
                      </TableCell>
                      <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                        {row[def.dateColumn] ? new Date(String(row[def.dateColumn])).toLocaleString() : "—"}
                      </TableCell>
                      <TableCell>
                        <Button variant="ghost" size="icon" disabled={deleteMutation.isPending} onClick={() => deleteMutation.mutate(String(row.id))}>
                          {deleteMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4 text-[#FF4D4D]" />}
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
    </div>
  );
}

function CreateForm({ entity, onSubmit, loading }: { entity: EntityKey; onSubmit: (v: Record<string, unknown>) => void; loading: boolean }) {
  const def = entities[entity];
  const [values, setValues] = useState<Record<string, unknown>>({ severity: "medium" });

  const update = (k: string, v: unknown) => setValues((s) => ({ ...s, [k]: v }));

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        const cleaned: Record<string, unknown> = {};
        for (const f of def.fields) {
          const v = values[f.name];
          if (v === "" || v === undefined) continue;
          if (f.type === "number") cleaned[f.name] = Number(v);
          else cleaned[f.name] = v;
        }
        onSubmit(cleaned);
      }}
      className="space-y-3"
    >
      {def.fields.map((f) => (
        <div key={f.name}>
          <Label htmlFor={f.name}>{f.label}{f.required && <span className="ml-1 text-[#FF4D4D]">*</span>}</Label>
          {f.type === "textarea" ? (
            <Textarea id={f.name} required={f.required} value={String(values[f.name] ?? "")} onChange={(e) => update(f.name, e.target.value)} />
          ) : f.type === "severity" ? (
            <Select value={String(values[f.name] ?? "medium")} onValueChange={(v) => update(f.name, v)}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {severityEnum.options.map((o) => <SelectItem key={o} value={o}>{o}</SelectItem>)}
              </SelectContent>
            </Select>
          ) : f.type === "enum" ? (
            <Select value={String(values[f.name] ?? "")} onValueChange={(v) => update(f.name, v)}>
              <SelectTrigger><SelectValue placeholder="Select…" /></SelectTrigger>
              <SelectContent>
                {(f.options ?? []).map((o) => <SelectItem key={o} value={o}>{o}</SelectItem>)}
              </SelectContent>
            </Select>
          ) : f.type === "number" ? (
            <Input id={f.name} type="number" min={1} required={f.required} value={String(values[f.name] ?? "")} onChange={(e) => update(f.name, e.target.value)} />
          ) : (
            <Input id={f.name} required={f.required} value={String(values[f.name] ?? "")} onChange={(e) => update(f.name, e.target.value)} />
          )}
        </div>
      ))}
      <DialogFooter>
        <Button type="submit" disabled={loading}>{loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}Create</Button>
      </DialogFooter>
    </form>
  );
}

export function makeEntityRoute(entity: EntityKey) {
  return {
    loader: ({ context }: { context: { queryClient: import("@tanstack/react-query").QueryClient } }) =>
      context.queryClient.ensureQueryData(listQuery(entity)),
    component: () => <EntityManagementPage entity={entity} />,
    errorComponent: ({ error }: { error: Error }) => (
      <div className="p-12 text-center text-muted-foreground">Failed to load: {error.message}</div>
    ),
  };
}
