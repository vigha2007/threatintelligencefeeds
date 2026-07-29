import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Plus, Trash2, Loader2, ChevronLeft, ChevronRight } from "lucide-react";
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

/** Rows fetched from the server per page */
const SERVER_PAGE_SIZE = 200;

const sevColors: Record<string, string> = {
  critical: "#E05A52", high: "#E8A23C", medium: "#4F7EF7", low: "#34A853",
};

export function EntityManagementPage({ entity }: { entity: EntityKey }) {
  const def = entities[entity];
  const qc = useQueryClient();
  const list   = listEntity;
  const create = createEntity;
  const del    = deleteEntity;

  const [open, setOpen] = useState(false);
  const [page, setPage] = useState(1);

  const offset = (page - 1) * SERVER_PAGE_SIZE;

  const { data, isLoading, isError } = useQuery({
    queryKey: ["entity", entity, page],
    queryFn:  () => list({ data: { entity, limit: SERVER_PAGE_SIZE, offset } }),
    staleTime: 15_000,
    placeholderData: (prev) => prev,
  });

  const rows       = data?.rows  ?? [];
  const total      = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / SERVER_PAGE_SIZE));
  const start      = offset + 1;
  const end        = Math.min(offset + rows.length, total);

  const createMutation = useMutation({
    mutationFn: (values: Record<string, unknown>) => create({ data: { entity, values } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["entity", entity] });
      qc.invalidateQueries({ queryKey: ["dashboard-metrics"] });
      toast.success(`${def.singular} added successfully`);
      setOpen(false);
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => del({ data: { entity, id } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["entity", entity] });
      qc.invalidateQueries({ queryKey: ["dashboard-metrics"] });
      toast.success("Record deleted");
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-extrabold text-gray-800 font-poppins">{def.label}</h1>
          <p className="text-xs font-semibold text-gray-400 font-manrope mt-1">
            {isLoading ? "Loading records..." : (
              <>
                <span className="font-bold text-gray-600">{total.toLocaleString()}</span>
                {" total records"}
                {total > 0 && ` — showing ${start.toLocaleString()} to ${end.toLocaleString()}`}
              </>
            )}
          </p>
        </div>
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogTrigger asChild>
            <Button className="bg-[#C48A5A] text-white hover:bg-[#C48A5A]/90 rounded-xl font-semibold text-xs shadow-sm"><Plus className="mr-1 h-4 w-4" /> Add {def.singular}</Button>
          </DialogTrigger>
          <DialogContent className="max-w-lg bg-white border border-[#E4DEC6] rounded-3xl shadow-lg">
            <DialogHeader><DialogTitle className="text-gray-800 font-bold font-poppins">Add New {def.singular}</DialogTitle></DialogHeader>
            <CreateForm entity={entity} loading={createMutation.isPending} onSubmit={(v) => createMutation.mutate(v)} />
          </DialogContent>
        </Dialog>
      </motion.div>

      <div className="bg-white border border-[#E4DEC6]/60 rounded-3xl p-5 shadow-sm">
        {isError ? (
          <div className="p-8 text-center text-xs font-semibold text-[#E05A52]">Failed to load records. Please try again.</div>
        ) : isLoading ? (
          <div className="flex items-center justify-center p-12">
            <Loader2 className="h-6 w-6 animate-spin text-[#C48A5A]" />
          </div>
        ) : rows.length === 0 && total === 0 ? (
          <div className="p-8 text-center text-xs font-semibold text-gray-500 font-manrope">No records yet. Click "Add {def.singular}" to create one.</div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-b border-[#E4DEC6]/60 bg-[#FAF8F5]">
                    {def.fields.slice(0, 4).map((f) => <TableHead key={f.name} className="text-xs font-bold text-gray-400 font-manrope uppercase">{f.label}</TableHead>)}
                    <TableHead className="text-xs font-bold text-gray-400 font-manrope uppercase">Severity</TableHead>
                    <TableHead className="text-xs font-bold text-gray-400 font-manrope uppercase">Date</TableHead>
                    <TableHead className="w-12"></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((row) => {
                    const sev = String(row.severity ?? "");
                    return (
                      <TableRow key={String(row.id)} className="border-b border-[#E4DEC6]/40 hover:bg-[#FAF8F5]/30">
                        {def.fields.slice(0, 4).map((f) => (
                          <TableCell key={f.name} className="max-w-[260px] truncate text-xs font-semibold text-gray-700 font-manrope">
                            {f.name === "severity" ? null : String(row[f.name] ?? "—")}
                          </TableCell>
                        ))}
                        <TableCell>
                          <span className="rounded-full px-2.5 py-0.5 text-[9px] font-bold uppercase tracking-wider font-poppins" style={{ background: `${sevColors[sev]}10`, color: sevColors[sev], border: `1px solid ${sevColors[sev]}25` }}>
                            {sev}
                          </span>
                        </TableCell>
                        <TableCell className="whitespace-nowrap text-xs text-gray-500 font-manrope">
                          {row[def.dateColumn] ? new Date(String(row[def.dateColumn])).toLocaleString() : "—"}
                        </TableCell>
                        <TableCell>
                          <Button variant="ghost" size="icon" disabled={deleteMutation.isPending} onClick={() => deleteMutation.mutate(String(row.id))} className="hover:bg-red-50 rounded-lg">
                            {deleteMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin text-gray-400" /> : <Trash2 className="h-4 w-4 text-[#E05A52]" />}
                          </Button>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>

            <div className="mt-4 flex items-center justify-between border-t border-[#E4DEC6]/40 pt-4">
              <span className="text-[11px] font-bold text-gray-400 font-manrope">
                Page {page.toLocaleString()} of {totalPages.toLocaleString()}
              </span>
              <div className="flex items-center gap-2">
                <Button variant="outline" size="sm" disabled={page === 1} onClick={() => setPage(1)} className="rounded-xl border-[#E4DEC6] text-gray-600 text-xs font-semibold">
                  First
                </Button>
                <Button variant="outline" size="icon" disabled={page === 1} onClick={() => setPage((p) => Math.max(1, p - 1))} className="rounded-xl border-[#E4DEC6] text-gray-600">
                  <ChevronLeft className="h-4 w-4" />
                </Button>
                <Button variant="outline" size="icon" disabled={page >= totalPages} onClick={() => setPage((p) => Math.min(totalPages, p + 1))} className="rounded-xl border-[#E4DEC6] text-gray-600">
                  <ChevronRight className="h-4 w-4" />
                </Button>
                <Button variant="outline" size="sm" disabled={page >= totalPages} onClick={() => setPage(totalPages)} className="rounded-xl border-[#E4DEC6] text-gray-600 text-xs font-semibold">
                  Last
                </Button>
              </div>
            </div>
          </>
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
      className="space-y-4 pt-2"
    >
      {def.fields.map((f) => (
        <div key={f.name} className="space-y-1">
          <Label htmlFor={f.name} className="text-xs font-bold text-gray-500 font-manrope">{f.label}{f.required && <span className="ml-1 text-[#E05A52]">*</span>}</Label>
          {f.type === "textarea" ? (
            <Textarea id={f.name} required={f.required} value={String(values[f.name] ?? "")} onChange={(e) => update(f.name, e.target.value)} className="bg-[#FAF8F5] border-[#E4DEC6] text-gray-800 rounded-xl" />
          ) : f.type === "severity" ? (
            <Select value={String(values[f.name] ?? "medium")} onValueChange={(v) => update(f.name, v)}>
              <SelectTrigger className="bg-[#FAF8F5] border-[#E4DEC6] text-gray-800 rounded-xl"><SelectValue /></SelectTrigger>
              <SelectContent className="bg-white border border-[#E4DEC6] rounded-xl">
                {severityEnum.options.map((o) => <SelectItem key={o} value={o} className="text-gray-800">{o}</SelectItem>)}
              </SelectContent>
            </Select>
          ) : f.type === "enum" ? (
            <Select value={String(values[f.name] ?? "")} onValueChange={(v) => update(f.name, v)}>
              <SelectTrigger className="bg-[#FAF8F5] border-[#E4DEC6] text-gray-800 rounded-xl"><SelectValue placeholder="Select…" /></SelectTrigger>
              <SelectContent className="bg-white border border-[#E4DEC6] rounded-xl">
                {(f.options ?? []).map((o) => <SelectItem key={o} value={o} className="text-gray-800">{o}</SelectItem>)}
              </SelectContent>
            </Select>
          ) : f.type === "number" ? (
            <Input id={f.name} type="number" min={1} required={f.required} value={String(values[f.name] ?? "")} onChange={(e) => update(f.name, e.target.value)} className="bg-[#FAF8F5] border-[#E4DEC6] text-gray-800 rounded-xl" />
          ) : (
            <Input id={f.name} required={f.required} value={String(values[f.name] ?? "")} onChange={(e) => update(f.name, e.target.value)} className="bg-[#FAF8F5] border-[#E4DEC6] text-gray-800 rounded-xl" />
          )}
        </div>
      ))}
      <DialogFooter className="pt-2">
        <Button type="submit" disabled={loading} className="bg-[#C48A5A] text-white hover:bg-[#C48A5A]/90 rounded-xl font-semibold shadow-sm w-full sm:w-auto">
          {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}Create Entry
        </Button>
      </DialogFooter>
    </form>
  );
}

export function makeEntityRoute(entity: EntityKey) {
  return {
    component: () => <EntityManagementPage entity={entity} />,
    errorComponent: ({ error }: { error: Error }) => (
      <div className="p-12 text-center text-muted-foreground">Failed to load: {error.message}</div>
    ),
  };
}
